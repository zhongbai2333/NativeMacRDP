#import "daemon/RDPSession.h"
#import "daemon/DisplayControl.h"
#import "daemon/Authenticator.h"
#import "protocol/RDPPeer.h"
#import "display/VirtualDisplay.h"
#import "display/ScreenCapture.h"
#import "display/FrameEncoder.h"
#import "display/CursorCapture.h"
#import "input/InputInjector.h"
#import "input/RDPCursorPositionPolicy.h"
#import "input/ClipboardSync.h"
#import "audio/AudioCapture.h"
#import "audio/AudioRedirect.h"
#import <sys/socket.h>
#import <unistd.h>
#include <math.h>
#include <string.h>
#include <freerdp/freerdp.h>
#include <freerdp/error.h>
#include <openssl/crypto.h>
#define RDP_LOG_COMPONENT "session"
#include "logging/RDPLog.h"

static const uint32_t kDefaultWidth   = 1920;
static const uint32_t kDefaultHeight  = 1080;
static const uint32_t kDefaultBitrate = 8000;

@interface RDPSession ()
@property (nonatomic, assign) int fd;
@property (nonatomic, assign) RDPSessionState sessionState;
@property (nonatomic, strong) NSString *address;
@property (nonatomic, assign) freerdp_peer *peer;
@property (nonatomic, strong) VirtualDisplay  *display;
@property (nonatomic, strong) DisplayControl  *displayControl;
@property (nonatomic, strong) ScreenCapture   *capture;
@property (nonatomic, strong) FrameEncoder    *encoder;
@property (nonatomic, assign) BOOL encoderStarted;
@property (nonatomic, strong) InputInjector   *injector;
@property (nonatomic, strong) ClipboardSync   *clipboard;
@property (nonatomic, strong) AudioCapture    *audio;
@property (nonatomic, strong) dispatch_queue_t audioSendQueue;
@property (nonatomic, strong) dispatch_semaphore_t audioSendSlots;
@property (nonatomic, strong) CursorCapture   *cursor;
@property (nonatomic, strong) dispatch_queue_t sessionQueue;
/* Signaled exactly once when teardown completes; lets the takeover path wait
 * for this session's display to be released without touching the main queue. */
@property (nonatomic, strong) dispatch_semaphore_t teardownSem;
/* Set once this session has authenticated + become the active session, so we
 * skip re-authenticating / re-activating on a subsequent Activate (mstsc may
 * re-activate on a resize). Guarded by the serial session queue. */
@property (nonatomic, assign) BOOL activated;
@property (nonatomic, assign) uint32_t desktopWidth;
@property (nonatomic, assign) uint32_t desktopHeight;
@property (nonatomic, strong, nullable) NSData *reconnectCookie;
@property (nonatomic, strong) dispatch_semaphore_t resumeSem;
@property (nonatomic, assign) BOOL explicitDisconnect;
@property (nonatomic, assign) BOOL replacementDisconnect;
@property (nonatomic, assign) BOOL retainedDesktopTransferred;
@property (nonatomic, assign) RDPCursorPositionEchoMode cursorPositionEchoMode;
- (BOOL)resizeDisplayToWidth:(uint32_t)width height:(uint32_t)height;
- (BOOL)startGraphicsAndInputWithWidth:(uint32_t)width
                                height:(uint32_t)height
                             displayID:(CGDirectDisplayID)displayID;
@end

@implementation RDPSession

- (instancetype)initWithFileDescriptor:(int)fd clientAddress:(NSString *)address {
    if ((self = [super init])) {
        _fd             = fd;
        _address        = [address copy];
        _sessionState   = RDPSessionStateConnecting;
        _sessionQueue   = dispatch_queue_create("com.macosrdp.session",
                                                DISPATCH_QUEUE_SERIAL);
        _teardownSem    = dispatch_semaphore_create(0);
        _resumeSem      = dispatch_semaphore_create(0);
        _audioSendQueue = dispatch_queue_create("com.macosrdp.audio-send",
                                                DISPATCH_QUEUE_SERIAL);
        /* Bound queued PCM to a short jitter window. The sender is no longer
         * given absolute transport priority, so this absorbs a large video
         * write without allowing stale audio to build for seconds. */
        _audioSendSlots = dispatch_semaphore_create(24);
        const char *cursorPositionEcho = getenv("RDP_CURSOR_POSITION_ECHO");
        _cursorPositionEchoMode = rdp_cursor_position_echo_mode(
            cursorPositionEcho);
        rdp_info("cursor position echo: %s%s",
                 rdp_cursor_position_echo_mode_name(_cursorPositionEchoMode),
                 cursorPositionEcho ? "" : " (default)");
    }
    return self;
}

- (int)clientFd             { return _fd; }
- (RDPSessionState)state    { return _sessionState; }
- (NSString *)clientAddress { return _address; }

- (void)start {
    rdp_info("starting session for %s", _address.UTF8String);
    dispatch_async(_sessionQueue, ^{ [self setupAndRun]; });
}

- (void)setupAndRun {
    rdp_verbose("creating RDP peer for fd=%d", _fd);
    BOOL offerReliableUDP = YES;
    if ([self.delegate respondsToSelector:
            @selector(sessionShouldOfferReliableUDP:)]) {
        offerReliableUDP = [self.delegate sessionShouldOfferReliableUDP:self];
    }
    RDPPeerCallbacks cb = {
        .onKeyboard  = rdp_on_keyboard,
        .onUnicodeKeyboard = rdp_on_unicode_keyboard,
        .onKeyboardReset = rdp_on_keyboard_reset,
        .onMouse     = rdp_on_mouse,
        .onMouseEx   = rdp_on_mouse_ex,
        .onClipboard = rdp_on_clipboard,
        .onClipboardFiles = rdp_on_clipboard_files,
        .onReady     = rdp_on_ready,
        .onDisplayResize = rdp_on_display_resize,
        .onKeyframeRequest = rdp_on_keyframe_request,
        .onMultitransportBootstrap = rdp_on_multitransport_bootstrap,
        .onDVCTunnelSend = rdp_on_dvc_tunnel_send,
        .onFrameRateChange = rdp_on_frame_rate_change,
        .allowMultitransport = offerReliableUDP ? true : false,
        .userdata    = (__bridge void *)self,
    };

    _peer = rdp_peer_create(_fd, &cb);
    if (!_peer) {
        rdp_error("rdp_peer_create failed for %s", _address.UTF8String);
        [self endWithError:[NSError errorWithDomain:@"RDPError" code:1
                            userInfo:@{NSLocalizedDescriptionKey: @"peer_create failed"}]];
        return;
    }

    _sessionState = RDPSessionStateNegotiating;
    rdp_verbose("RDP negotiation started with %s", _address.UTF8String);

    /* Negotiation watchdog: if the client doesn't complete RDP activation within
     * kNegotiationTimeoutSecs, drop the connection. Without this, a half-open or
     * stalled TLS handshake holds the peer for FreeRDP's full 2-minute read timeout,
     * making every reconnect attempt appear dead to the user. */
    static const NSTimeInterval kNegotiationTimeoutSecs = 20.0;
    NSDate *negoDeadline = [NSDate dateWithTimeIntervalSinceNow:kNegotiationTimeoutSecs];

    uint32_t lastAudioRate = 0;
    while (_sessionState != RDPSessionStateDisconnecting &&
           _sessionState != RDPSessionStateDisconnected) {
        if (!rdp_peer_run_once(_peer)) {
            rdp_verbose("peer loop ended for %s", _address.UTF8String);
            break;
        }
        /* Abort if still negotiating past the deadline. */
        if (_sessionState == RDPSessionStateNegotiating &&
            [[NSDate date] compare:negoDeadline] == NSOrderedDescending) {
            rdp_info("negotiation timeout (%gs) for %s — dropping stale connection",
                     kNegotiationTimeoutSecs, _address.UTF8String);
            break;
        }
        /* rdpsnd format negotiation completes asynchronously (Activated callback)
         * AFTER audio capture starts. The client plays our PCM at the rate IT
         * selected — rdpsnd does not resample — so the tap must be resampled to
         * that exact rate or the audio is pitch-shifted. Poll the negotiated rate
         * and push it to AudioCapture once known/changed. Cheap; the setter
         * no-ops when unchanged. */
        if (_audio) {
            uint32_t rate = rdp_peer_get_audio_rate(_peer);
            if (rate && rate != lastAudioRate) {
                _audio.outputSampleRate = rate;
                rdp_info("audio playback rate negotiated: %u Hz — "
                         "tap resampled to match (no pitch shift)", (unsigned)rate);
                lastAudioRate = rate;
            }
        }
    }

    if (_sessionState == RDPSessionStateActive && !_explicitDisconnect &&
        rdp_peer_disconnect_is_reconnectable(_peer) &&
        _reconnectCookie.length == sizeof(ARC_CS_PRIVATE_PACKET)) {
        /* Open the per-address circuit breaker before mstsc starts its automatic
         * reconnect. Waiting for the detached UDP object to report failure is
         * too late: mstsc commonly creates the replacement TCP peer immediately,
         * so that peer would advertise UDP and repeat the broken Soft-Sync loop. */
        if (rdp_peer_is_udp_soft_sync_active(_peer) &&
            [self.delegate respondsToSelector:
                @selector(sessionReliableUDPTunnelDidFailAfterSoftSync:)]) {
            [self.delegate sessionReliableUDPTunnelDidFailAfterSoftSync:self];
        }
        [self suspendForReconnect];
    } else {
        [self teardown];
    }
}

static void rdp_on_ready(void *ud, uint32_t w, uint32_t h, uint32_t depth) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_info("client activated: %ux%u @%ubpp", w, h, depth);
    /* Called from peer_activate INSIDE the peer loop, which already runs on the
     * serial sessionQueue. dispatch_async back onto that same queue would starve
     * this behind the blocking loop — it would only run after the loop exits and
     * teardown has freed _peer (use-after-free crash), and media would never be
     * set up during a live session. Run it inline: the peer is alive here. */
    [self setupDisplayAndMediaForWidth:w height:h];
}

static bool rdp_on_display_resize(void *ud, uint32_t width, uint32_t height) {
    RDPSession *self = (__bridge RDPSession *)ud;
    return [self resizeDisplayToWidth:width height:height] ? true : false;
}

static void rdp_on_frame_rate_change(void *ud, uint32_t framesPerSecond) {
    RDPSession *self = (__bridge RDPSession *)ud;
    [self.capture setPreferredFrameRate:framesPerSecond];
}

static void rdp_on_keyboard(void *ud, uint16_t flags, uint16_t code) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("key flags=0x%04x code=0x%02x", flags, code);
    [self.capture noteRemoteInputActivity];
    [self.injector injectKeyEvent:flags scanCode:code];
}

static void rdp_on_unicode_keyboard(void *ud, uint16_t flags, uint16_t code) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("unicode key flags=0x%04x code=U+%04X", flags, code);
    [self.capture noteRemoteInputActivity];
    [self.injector injectUnicodeKeyEvent:flags codeUnit:code];
}

static void rdp_on_keyboard_reset(void *ud) {
    RDPSession *self = (__bridge RDPSession *)ud;
    [self.injector resetKeyboardState];
}

static void rdp_on_mouse(void *ud, uint16_t flags, uint16_t x, uint16_t y) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("mouse flags=0x%04x x=%u y=%u", flags, x, y);
    [self.capture noteRemoteInputActivity];
    const BOOL wheel = (flags & (RDP_PTR_WHEEL | RDP_PTR_HWHEEL)) != 0;
    /* Desktop clients move their pointer locally. Echoing every move forces
     * mstsc to obey a stale, round-tripped position and visibly stutters over
     * a WAN/FRP path. The default buttons mode still synchronizes tap/click
     * coordinates for touch clients without feeding ordinary motion back. */
    if (rdp_cursor_should_echo_position(self.cursorPositionEchoMode,
                                        flags, false))
        rdp_peer_send_cursor_position(self.peer, x, y);
    if (wheel)
        [self.injector injectMouseWheelEvent:flags x:x y:y];
    else
        [self.injector injectMouseEvent:flags x:x y:y];
}

static void rdp_on_mouse_ex(void *ud, uint16_t flags, uint16_t x, uint16_t y) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("mouse_ex flags=0x%04x x=%u y=%u", flags, x, y);
    [self.capture noteRemoteInputActivity];
    if (rdp_cursor_should_echo_position(self.cursorPositionEchoMode,
                                        flags, true))
        rdp_peer_send_cursor_position(self.peer, x, y);
    [self.injector injectMouseEvent:flags x:x y:y];
}

static void rdp_on_clipboard(void *ud, const uint8_t *data, size_t len,
                              uint32_t format) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_verbose("clipboard from client: format=0x%08x len=%zu", format, len);
    [self.clipboard receiveFromClient:data length:len format:format];
}

static bool rdp_on_clipboard_files(void *ud, const char *const *paths,
                                   size_t count) {
    RDPSession *self = (__bridge RDPSession *)ud;
    if (!self.clipboard || !paths || count == 0) return false;
    return [self.clipboard receiveFilesFromClientPaths:paths count:count]
               ? true : false;
}

static void rdp_on_keyframe_request(void *ud) {
    RDPSession *self = (__bridge RDPSession *)ud;
    rdp_debug("keyframe requested by peer");
    [self.encoder forceKeyframe];
}

static bool rdp_on_multitransport_bootstrap(void *ud, uint32_t requestID,
                                            const uint8_t cookie[16]) {
    RDPSession *self = (__bridge RDPSession *)ud;
    NSData *cookieData = [NSData dataWithBytes:cookie length:16];
    id<RDPSessionDelegate> delegate = self.delegate;
    if (![delegate respondsToSelector:
            @selector(session:didOfferMultitransportRequestID:securityCookie:)])
        return false;
    BOOL accepted = [delegate session:self
        didOfferMultitransportRequestID:requestID
                         securityCookie:cookieData];
    rdp_info("UDP bootstrap request %u %s for %s", requestID,
             accepted ? "registered" : "rejected",
             self.clientAddress.UTF8String);
    return accepted;
}

static bool rdp_on_dvc_tunnel_send(void *ud, const uint8_t *data, size_t len) {
    RDPSession *self = (__bridge RDPSession *)ud;
    if (!data || !len) return false;
    id<RDPSessionDelegate> delegate = self.delegate;
    if (![delegate respondsToSelector:
            @selector(session:sendUdpDynamicChannelData:)])
        return false;
    NSData *copy = [NSData dataWithBytes:data length:len];
    return [delegate session:self sendUdpDynamicChannelData:copy] ? true : false;
}

- (void)udpTunnelDidBecomeReady {
    @synchronized(self) {
        if (_peer && _sessionState != RDPSessionStateDisconnecting &&
            _sessionState != RDPSessionStateDisconnected) {
            rdp_peer_set_udp_tunnel_ready(_peer, true);
            rdp_info("authenticated reliable UDP tunnel attached to %s",
                     _address.UTF8String);
        }
    }
}

- (void)udpTunnelDidFail {
    BOOL softSyncActive = NO;
    @synchronized(self) {
        if (_peer) {
            rdp_peer_set_udp_tunnel_ready(_peer, false);
            softSyncActive = rdp_peer_is_udp_soft_sync_active(_peer) ? YES : NO;
        }
    }
    if (softSyncActive) {
        /* MS-RDPEDYC defines the TCP->UDP Soft-Sync transition but no reverse
         * transition. Continuing would strand GFX on a dead tunnel, so make
         * the failure explicit and let Windows App reconnect over TCP. */
        rdp_error("reliable UDP tunnel failed after Soft-Sync; disconnecting %s",
                  _address.UTF8String);
        if ([self.delegate respondsToSelector:
                @selector(sessionReliableUDPTunnelDidFailAfterSoftSync:)]) {
            [self.delegate sessionReliableUDPTunnelDidFailAfterSoftSync:self];
        }
        [self disconnect];
    } else {
        rdp_info("reliable UDP setup failed before Soft-Sync; continuing %s on TCP",
                 _address.UTF8String);
    }
}

- (BOOL)receiveUdpDynamicChannelData:(NSData *)data {
    if (!data.length) return NO;
    @synchronized(self) {
        if (!_peer || _sessionState == RDPSessionStateDisconnecting ||
            _sessionState == RDPSessionStateDisconnected)
            return NO;
        return rdp_peer_receive_udp_dvc(_peer, data.bytes, data.length) ? YES : NO;
    }
}

- (void)updateUDPTransportStats:(const RDPUDP2Stats *)stats
                   observedAtMS:(uint64_t)observedAtMS
                    queuedBytes:(uint32_t)queuedBytes {
    if (!stats) return;
    @synchronized(self) {
        if (!_peer || _sessionState == RDPSessionStateDisconnecting ||
            _sessionState == RDPSessionStateDisconnected)
            return;
        const double cwnd = stats->congestion_window_packets;
        RDPPeerUDPTransportMetrics metrics = {
            .observedAtMS = observedAtMS,
            .retransmissions = stats->datagrams_retransmitted,
            .lossEvents = stats->loss_events,
            .smoothedRTTMS = stats->smoothed_rtt_ms,
            .inflightPackets = stats->inflight_packets > UINT32_MAX
                ? UINT32_MAX : (uint32_t)stats->inflight_packets,
            .congestionWindowPackets = cwnd >= (double)UINT32_MAX
                ? UINT32_MAX : (uint32_t)ceil(cwnd),
            .queuedBytes = queuedBytes,
        };
        rdp_peer_update_udp_transport_metrics(_peer, &metrics);
    }
}

- (BOOL)startGraphicsAndInputWithWidth:(uint32_t)width
                                height:(uint32_t)height
                             displayID:(CGDirectDisplayID)displayID {
    _encoderStarted = NO;
    _encoder = [[FrameEncoder alloc] initWithWidth:width height:height
                                           bitrate:kDefaultBitrate];
    __weak typeof(self) weak = self;
    _encoder.outputHandler = ^(const uint8_t *data, size_t len, BOOL keyFrame,
                               uint16_t dx, uint16_t dy, uint16_t dw, uint16_t dh) {
        rdp_peer_send_h264_frame(weak.peer, data, len, width, height,
                                 keyFrame ? true : false, dx, dy, dw, dh);
    };

    _capture = [[ScreenCapture alloc] initWithDisplayID:displayID];
    _capture.frameHandler = ^(IOSurfaceRef surface, uint32_t fw, uint32_t fh,
                               const ScreenCaptureDirtyRegion *dirtyRegion) {
        (void)fw; (void)fh;
        RECTANGLE_16 rects[SCREEN_CAPTURE_MAX_DIRTY_RECTS] = {0};
        uint32_t rectCount = 0;
        uint32_t unionLeft = width, unionTop = height;
        uint32_t unionRight = 0, unionBottom = 0;
        uint32_t sourceCount = dirtyRegion ? dirtyRegion->count : 0;
        for (uint32_t i = 0;
             i < sourceCount && rectCount < SCREEN_CAPTURE_MAX_DIRTY_RECTS; i++) {
            CGRect dirty = dirtyRegion->rects[i];
            double minX = MAX(0.0, floor(CGRectGetMinX(dirty)));
            double minY = MAX(0.0, floor(CGRectGetMinY(dirty)));
            double maxX = MIN((double)width, ceil(CGRectGetMaxX(dirty)));
            double maxY = MIN((double)height, ceil(CGRectGetMaxY(dirty)));
            if (minX >= maxX || minY >= maxY) continue;
            RECTANGLE_16 rect = {
                .left = (uint16_t)minX, .top = (uint16_t)minY,
                .right = (uint16_t)maxX, .bottom = (uint16_t)maxY,
            };
            rects[rectCount++] = rect;
            if (rect.left < unionLeft) unionLeft = rect.left;
            if (rect.top < unionTop) unionTop = rect.top;
            if (rect.right > unionRight) unionRight = rect.right;
            if (rect.bottom > unionBottom) unionBottom = rect.bottom;
        }
        if (rectCount == 0) {
            rects[0] = (RECTANGLE_16){ .left = 0, .top = 0,
                                      .right = (uint16_t)width,
                                      .bottom = (uint16_t)height };
            rectCount = 1;
            unionLeft = unionTop = 0;
            unionRight = width;
            unionBottom = height;
        }
        uint16_t dx = (uint16_t)unionLeft;
        uint16_t dy = (uint16_t)unionTop;
        uint16_t dw = (uint16_t)(unionRight - unionLeft);
        uint16_t dh = (uint16_t)(unionBottom - unionTop);
        RDPGraphicsMode mode = rdp_peer_graphics_mode(weak.peer);
        if (mode == RDPGraphicsModeAVC420) {
            if (!weak.encoderStarted) {
                if (![weak.encoder start]) {
                    rdp_error("H.264 encoder failed to start");
                    return;
                }
                weak.encoderStarted = YES;
                [weak.encoder forceKeyframe];
            }
            [weak.encoder encodeFrame:surface dirtyX:dx dirtyY:dy
                                dirtyW:dw dirtyH:dh];
        } else if (mode == RDPGraphicsModeProgressive) {
            uint32_t changedTiles = 0;
            rdp_peer_send_progressive_frame(weak.peer, surface, width, height,
                                            rects, rectCount, &changedTiles);
            uint32_t totalTiles = ((width + 63u) / 64u) *
                                  ((height + 63u) / 64u);
            uint32_t activeThreshold = MAX(16u, totalTiles / 50u);
            if (changedTiles >= activeThreshold)
                [weak.capture noteVisualActivity];
        }
    };
    if (![_capture startWithWidth:width height:height]) {
        rdp_error("screen capture FAILED on displayID=%u at %ux%u", displayID,
                  width, height);
        _capture = nil;
        _encoder = nil;
        return NO;
    }

    _injector = [[InputInjector alloc] initWithDisplayID:displayID
                                             sourceWidth:width
                                            sourceHeight:height];
    /* Clear modifier key-down state that may have survived a dropped/restarted
     * RDP process before the client can submit its first text PDU. */
    [_injector resetKeyboardState];
    _desktopWidth = width;
    _desktopHeight = height;

    rdp_peer_send_default_cursor(_peer);
    const char *curShapes = getenv("RDP_CURSOR_SHAPES");
    if (curShapes && strcmp(curShapes, "1") == 0) {
        _cursor = [[CursorCapture alloc] init];
        _cursor.handler = ^(const uint8_t *bgra, uint32_t cw, uint32_t ch,
                            uint16_t hotX, uint16_t hotY) {
            rdp_peer_send_cursor_shape(weak.peer, bgra, cw, ch, hotX, hotY);
        };
        [_cursor start];
    }
    rdp_info("graphics/input bound to retained displayID=%u at %ux%u",
             displayID, width, height);
    return YES;
}

- (BOOL)resizeDisplayToWidth:(uint32_t)width height:(uint32_t)height {
    if (!_activated || !_display || width == 0 || height == 0) return NO;
    if (width == _desktopWidth && height == _desktopHeight) return YES;

    uint32_t oldWidth = _desktopWidth;
    uint32_t oldHeight = _desktopHeight;
    CGDirectDisplayID oldDisplayID = _display.displayID;
    [_cursor stop]; _cursor = nil;
    [_capture stop]; _capture = nil;
    [_encoder stop]; _encoder = nil;
    _injector = nil;

    if (![_display resizeToWidth:width height:height]) {
        rdp_error("display resize rejected; restoring capture at %ux%u",
                  oldWidth, oldHeight);
        (void)[self startGraphicsAndInputWithWidth:oldWidth height:oldHeight
                                         displayID:oldDisplayID];
        return NO;
    }
    if (![self startGraphicsAndInputWithWidth:width height:height
                                    displayID:_display.displayID]) {
        rdp_error("capture restart failed after display resize to %ux%u", width, height);
        return NO;
    }
    rdp_info("session media resized without desktop teardown: %ux%u", width, height);
    return YES;
}

- (void)setupDisplayAndMediaForWidth:(uint32_t)w height:(uint32_t)h {
    /* mstsc can re-activate (e.g. on a client-side resize). We only authenticate
     * and bring the display up once — re-entry after we're active is a no-op. */
    if (_activated || _sessionState == RDPSessionStateActive) {
        rdp_verbose("re-activation ignored (session already active) for %s",
                    _address.UTF8String);
        return;
    }

    /* A reconnecting client proves possession of the previous connection's
     * opaque ARC verifier. On a match, RDPServer has already transferred the
     * retained BetterDisplay desktop to this session, so no password prompt or
     * desktop creation is needed. A missing/invalid proof falls through to the
     * ordinary local-account authentication path. */
    BOOL resumed = NO;
    ARC_CS_PRIVATE_PACKET incoming = {0};
    if (rdp_peer_get_incoming_reconnect_cookie(_peer, &incoming) &&
        [self.delegate respondsToSelector:
            @selector(session:requestResumeWithReconnectCookie:)]) {
        NSData *proof = [NSData dataWithBytes:&incoming length:sizeof(incoming)];
        resumed = [self.delegate session:self
               requestResumeWithReconnectCookie:proof];
    }

    /* ── Authenticate BEFORE creating any virtual display ─────────────────────
     * Credentials arrived in the RDP logon (peer_activate captured them). Validate
     * against the local macOS account. Fail-closed: bad/missing creds → tear the
     * connection down. This runs inline on the serial session queue (inside the
     * peer loop), so a synchronous check is safe. NEVER log the password. */
    if (!resumed) {
        const char *cuser = NULL, *cpass = NULL, *cdomain = NULL;
        rdp_peer_get_credentials(_peer, &cuser, &cpass, &cdomain);
        NSString *user   = cuser   ? [NSString stringWithUTF8String:cuser]   : nil;
        NSString *pass   = cpass   ? [NSString stringWithUTF8String:cpass]   : nil;
        NSString *domain = cdomain ? [NSString stringWithUTF8String:cdomain] : nil;

        if (![Authenticator validateUsername:user password:pass domain:domain]) {
            rdp_error("authentication FAILED for %s (user='%s') — rejecting connection",
                      _address.UTF8String, user.length ? user.UTF8String : "(none)");
            _sessionState = RDPSessionStateDisconnecting;
            return;
        }
        rdp_info("authentication OK for %s (user='%s')",
                 _address.UTF8String, user.length ? user.UTF8String : "(none)");
    } else {
        rdp_info("auto-reconnect proof accepted for %s; retained desktop adopted",
                 _address.UTF8String);
    }

    /* ── Become the single active session (takeover) ──────────────────────────
     * Ask the server to make us active. It signals any currently-active session
     * to disconnect and BLOCKS here until that old session has released its
     * virtual display, so we never have two virtual displays / two main displays
     * fighting. If it returns NO we were superseded (or the server is stopping)
     * and must abort. */
    if (!resumed && [self.delegate respondsToSelector:
                         @selector(sessionDidAuthenticateAndRequestActivation:)]) {
        if (![self.delegate sessionDidAuthenticateAndRequestActivation:self]) {
            rdp_info("activation refused for %s — aborting session", _address.UTF8String);
            _sessionState = RDPSessionStateDisconnecting;
            return;
        }
    }
    _activated = YES;

    uint32_t width  = w  ?: kDefaultWidth;
    uint32_t height = h ?: kDefaultHeight;

    rdp_info("setting up display %ux%u for %s", width, height, _address.UTF8String);

    if (!_display) {
        _display = [[VirtualDisplay alloc] initWithWidth:width height:height];
        if (![_display create]) {
            rdp_verbose("VirtualDisplay unavailable, falling back to main display");
            _display = nil;
        } else {
            rdp_verbose("VirtualDisplay created: displayID=%u", _display.displayID);
        }
    } else if ((_display.width != width || _display.height != height) &&
               ![_display resizeToWidth:width height:height]) {
        rdp_error("retained display could not resize from %ux%u to %ux%u",
                  _display.width, _display.height, width, height);
        _sessionState = RDPSessionStateDisconnecting;
        return;
    }

    CGDirectDisplayID displayID = _display ? _display.displayID : CGMainDisplayID();

    /* Wake the Mac + keep it awake for the whole session (replaces caffeinate),
     * and privacy-dim the BUILT-IN panel (brightness -> 0) so a bystander can't
     * watch the remote session. Pass the virtual display id so we never dim the
     * screen the remote actually captures. RDP_SHARED_MODE=1 skips dimming. */
    if (!_displayControl) {
        _displayControl = [[DisplayControl alloc] initWithVirtualDisplayID:displayID];
        [_displayControl start];
    }

    _encoder = [[FrameEncoder alloc] initWithWidth:width height:height
                                           bitrate:kDefaultBitrate];
    __weak typeof(self) weak = self;
    _encoder.outputHandler = ^(const uint8_t *data, size_t len, BOOL keyFrame,
                               uint16_t dx, uint16_t dy, uint16_t dw, uint16_t dh) {
        rdp_debug("encoded frame: len=%zu keyFrame=%d dirty=(%u,%u,%ux%u)",
                  len, keyFrame, dx, dy, dw, dh);
        rdp_peer_send_h264_frame(weak.peer, data, len, width, height,
                                 keyFrame ? true : false, dx, dy, dw, dh);
    };
    rdp_verbose("H.264 encoder prepared at %u kbps; start deferred until "
                "the client graphics mode is known", kDefaultBitrate);

    _capture = [[ScreenCapture alloc] initWithDisplayID:displayID];
    _capture.frameHandler = ^(IOSurfaceRef surface, uint32_t fw, uint32_t fh,
                               const ScreenCaptureDirtyRegion *dirtyRegion) {
        (void)fw; (void)fh;
        /* Preserve ScreenCaptureKit's disjoint damage rectangles for the
         * Progressive tile encoder. AVC currently accepts one metablock bound,
         * so also calculate their union for the dormant VideoToolbox path. */
        RECTANGLE_16 rects[SCREEN_CAPTURE_MAX_DIRTY_RECTS] = {0};
        uint32_t rectCount = 0;
        uint32_t unionLeft = width, unionTop = height, unionRight = 0, unionBottom = 0;
        uint32_t sourceCount = dirtyRegion ? dirtyRegion->count : 0;
        for (uint32_t i = 0;
             i < sourceCount && rectCount < SCREEN_CAPTURE_MAX_DIRTY_RECTS; i++) {
            CGRect dirty = dirtyRegion->rects[i];
            double minX = MAX(0.0, floor(CGRectGetMinX(dirty)));
            double minY = MAX(0.0, floor(CGRectGetMinY(dirty)));
            double maxX = MIN((double)width, ceil(CGRectGetMaxX(dirty)));
            double maxY = MIN((double)height, ceil(CGRectGetMaxY(dirty)));
            if (minX >= maxX || minY >= maxY) continue;

            RECTANGLE_16 rect = {
                .left = (uint16_t)minX,
                .top = (uint16_t)minY,
                .right = (uint16_t)maxX,
                .bottom = (uint16_t)maxY,
            };
            rects[rectCount++] = rect;
            if (rect.left < unionLeft) unionLeft = rect.left;
            if (rect.top < unionTop) unionTop = rect.top;
            if (rect.right > unionRight) unionRight = rect.right;
            if (rect.bottom > unionBottom) unionBottom = rect.bottom;
        }
        if (rectCount == 0) {
            rects[0] = (RECTANGLE_16){ .left = 0, .top = 0,
                                      .right = (uint16_t)width,
                                      .bottom = (uint16_t)height };
            rectCount = 1;
            unionLeft = unionTop = 0;
            unionRight = width;
            unionBottom = height;
        }
        uint16_t dx = (uint16_t)unionLeft;
        uint16_t dy = (uint16_t)unionTop;
        uint16_t dw = (uint16_t)(unionRight - unionLeft);
        uint16_t dh = (uint16_t)(unionBottom - unionTop);
        rdp_debug("captured frame: %u dirty rect(s), bounds=(%u,%u,%ux%u)",
                  rectCount, dx, dy, dw, dh);
        RDPGraphicsMode mode = rdp_peer_graphics_mode(weak.peer);
        if (mode == RDPGraphicsModeAVC420) {
            if (!weak.encoderStarted) {
                if (![weak.encoder start]) {
                    rdp_error("H.264 encoder failed to start");
                    return;
                }
                weak.encoderStarted = YES;
                [weak.encoder forceKeyframe];
                rdp_info("graphics path active: VideoToolbox AVC420");
            }
            [weak.encoder encodeFrame:surface dirtyX:dx dirtyY:dy
                                dirtyW:dw dirtyH:dh];
        } else if (mode == RDPGraphicsModeProgressive) {
            uint32_t changedTiles = 0;
            rdp_peer_send_progressive_frame(weak.peer, surface, width, height,
                                            rects, rectCount, &changedTiles);
            /* ScreenCaptureKit metadata over-reports GPU-backed window damage.
             * Reuse Progressive's exact pixel comparison instead: large real
             * motion such as video keeps 60 Hz, while clocks/carets can idle. */
            uint32_t totalTiles = ((width + 63u) / 64u) *
                                  ((height + 63u) / 64u);
            uint32_t activeThreshold = MAX(16u, totalTiles / 50u);
            if (changedTiles >= activeThreshold)
                [weak.capture noteVisualActivity];
        }
    };
    if ([_capture startWithWidth:width height:height])
        rdp_verbose("screen capture started on displayID=%u", displayID);
    else
        rdp_error("screen capture FAILED on displayID=%u — desktop will be black "
                  "until Screen Recording is granted", displayID);

    _injector  = [[InputInjector alloc] initWithDisplayID:displayID
                                              sourceWidth:width
                                             sourceHeight:height];
    /* Initial connections still use this setup path (the helper above is used
     * for retained-display resize/rebuild). Reset here as well so a key-down
     * left by a prior daemon process cannot survive the first connection. */
    [_injector resetKeyboardState];
    _desktopWidth = width;
    _desktopHeight = height;
    _clipboard = [[ClipboardSync alloc] init];
    _clipboard.sendToClientBlock = ^(const uint8_t *data, size_t len, uint32_t fmt) {
        rdp_verbose("sending clipboard to client: format=0x%08x len=%zu", fmt, len);
        rdp_peer_send_clipboard(weak.peer, data, len, fmt);
    };
    _clipboard.sendFilesToClientBlock = ^(NSArray<NSString *> *paths) {
        typeof(self) self_ = weak;
        if (!self_ || paths.count == 0) return;
        const char **utf8Paths = calloc(paths.count, sizeof(*utf8Paths));
        if (!utf8Paths) {
            rdp_error("sending file clipboard: path array allocation failed");
            return;
        }
        for (NSUInteger i = 0; i < paths.count; i++)
            utf8Paths[i] = paths[i].fileSystemRepresentation;
        rdp_verbose("sending file clipboard to client: %zu file(s)",
                    (size_t)paths.count);
        rdp_peer_send_clipboard_files(self_.peer, utf8Paths, paths.count);
        free(utf8Paths);
    };
    [_clipboard start];

    /* Only start audio capture if the client actually declared audio support.
       Saves a CoreAudio IO proc registration for clients that don't want audio. */
    BOOL clientWantsAudio = freerdp_settings_get_bool(
        _peer->context->settings, FreeRDP_AudioPlayback);
    const char *audioOutputEnv = getenv("RDP_AUDIO_OUTPUT");
    BOOL audioOutputEnabled = !(audioOutputEnv &&
                                strcmp(audioOutputEnv, "0") == 0);
    if (clientWantsAudio && audioOutputEnabled) {
        _audio = [[AudioCapture alloc] init];
        _audio.captureBlock = ^(const int16_t *samples, uint32_t frameCount) {
            typeof(self) self_ = weak;
            if (!self_ || !samples || frameCount == 0) return;

            /* Never wait for the RDP transport on CoreAudio's IO callback.
             * Copy into a bounded queue and let a dedicated sender wait for the
             * socket; otherwise one large Progressive frame stalls CoreAudio
             * for seconds and produces the observed intermittent crackle. */
            if (dispatch_semaphore_wait(self_.audioSendSlots,
                                        DISPATCH_TIME_NOW) != 0)
                return;
            size_t bytes = (size_t)frameCount * 2u * sizeof(int16_t);
            int16_t *owned = malloc(bytes);
            if (!owned) {
                dispatch_semaphore_signal(self_.audioSendSlots);
                return;
            }
            memcpy(owned, samples, bytes);
            dispatch_async(self_.audioSendQueue, ^{
                typeof(self) strong = weak;
                if (strong && strong.peer)
                    rdp_peer_send_audio(strong.peer, owned, frameCount);
                free(owned);
                if (strong)
                    dispatch_semaphore_signal(strong.audioSendSlots);
            });
        };
        NSError *audioErr = nil;
        if (![_audio startWithError:&audioErr]) {
            rdp_verbose("audio capture unavailable: %s",
                        audioErr.localizedDescription.UTF8String);
        } else {
            rdp_verbose("audio capture started");
        }
    } else if (!audioOutputEnabled) {
        rdp_info("remote audio output disabled by RDP_AUDIO_OUTPUT=0 — capture skipped");
    } else {
        rdp_verbose("client did not request audio — capture skipped");
    }

    _sessionState = RDPSessionStateActive;
    ARC_CS_PRIVATE_PACKET expectedReconnect = {0};
    if (rdp_peer_get_expected_reconnect_cookie(_peer, &expectedReconnect))
        _reconnectCookie = [NSData dataWithBytes:&expectedReconnect
                                           length:sizeof(expectedReconnect)];
    rdp_info("session active for %s", _address.UTF8String);

    /* Advertise a client-side system cursor first so the very first pointer the
     * client gets is valid (and the cursor is smooth, decoupled from the video
     * frame rate) before the real shapes start streaming. */
    rdp_peer_send_default_cursor(_peer);

    /* Stream Mac cursor semantics (arrow, I-beam, crosshair, resize, hand, …)
     * as classic 24bpp RDP color-pointer PDUs. Native center-hotspot artwork is
     * normalized into deterministic compatibility shapes because Windows App
     * corrupts some macOS alpha bitmaps when represented as AND/XOR masks. */
    const char *curShapes = getenv("RDP_CURSOR_SHAPES");
    if (curShapes && strcmp(curShapes, "1") == 0) {
        _cursor = [[CursorCapture alloc] init];
        _cursor.handler = ^(const uint8_t *bgra, uint32_t cw, uint32_t ch,
                            uint16_t hotX, uint16_t hotY) {
            rdp_peer_send_cursor_shape(weak.peer, bgra, cw, ch, hotX, hotY);
        };
        [_cursor start];
        rdp_info("cursor-shape streaming ON (RDP_CURSOR_SHAPES=1)");
    } else {
        rdp_info("cursor-shape streaming OFF (default) — client draws the system "
                 "arrow; set RDP_CURSOR_SHAPES=1 to stream real Mac cursor shapes");
    }
}

- (BOOL)matchesReconnectCookie:(NSData *)reconnectCookie {
    if (reconnectCookie.length != sizeof(ARC_CS_PRIVATE_PACKET)) return NO;
    @synchronized(self) {
        if (_sessionState != RDPSessionStateSuspended ||
            _reconnectCookie.length != reconnectCookie.length ||
            !_display || _retainedDesktopTransferred)
            return NO;
        return CRYPTO_memcmp(_reconnectCookie.bytes, reconnectCookie.bytes,
                             reconnectCookie.length) == 0;
    }
}

- (BOOL)adoptRetainedDesktopFromSession:(RDPSession *)session {
    if (!session || session == self) return NO;
    @synchronized(session) {
        if (session.sessionState != RDPSessionStateSuspended ||
            !session.display || session.retainedDesktopTransferred)
            return NO;
        @synchronized(self) {
            _display = session.display;
            _displayControl = session.displayControl;
            _desktopWidth = _display.width;
            _desktopHeight = _display.height;
        }
        session.display = nil;
        session.displayControl = nil;
        session.retainedDesktopTransferred = YES;
        dispatch_semaphore_signal(session.resumeSem);
    }
    return YES;
}

- (void)suspendForReconnect {
    rdp_info("network interruption: retaining desktop for fast reconnect (%s)",
             _address.UTF8String);
    [_cursor stop]; _cursor = nil;
    [_capture stop]; _capture = nil;
    [_encoder stop]; _encoder = nil;
    [_audio stop]; _audio = nil;
    if (_audioSendQueue) dispatch_sync(_audioSendQueue, ^{});
    [_clipboard stop]; _clipboard = nil;
    _injector = nil;

    BOOL explicitlyDisconnected = NO;
    @synchronized(self) {
        /* disconnect may race the peer-loop exit. Never overwrite its
         * Disconnecting state with Suspended or retain a desktop the user
         * intentionally closed. */
        explicitlyDisconnected = _explicitDisconnect ||
                                 _sessionState == RDPSessionStateDisconnecting;
        if (!explicitlyDisconnected) {
            if (_peer) { rdp_peer_destroy(_peer); _peer = NULL; }
            if (_fd >= 0) { close(_fd); _fd = -1; }
            _sessionState = RDPSessionStateSuspended;
        }
    }
    if (explicitlyDisconnected) {
        [self teardown];
        return;
    }

    NSTimeInterval grace = 20.0;
    const char *graceEnv = getenv("RDP_RECONNECT_GRACE_SECONDS");
    if (graceEnv && *graceEnv) {
        char *end = NULL;
        double parsed = strtod(graceEnv, &end);
        if (end && *end == '\0' && parsed >= 5.0 && parsed <= 120.0)
            grace = parsed;
    }
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW,
                                             (int64_t)(grace * NSEC_PER_SEC));
    long resumed = dispatch_semaphore_wait(_resumeSem, deadline);

    @synchronized(self) {
        if (!_retainedDesktopTransferred) {
            [_displayControl stop]; _displayControl = nil;
            [_display destroy]; _display = nil;
            if (resumed != 0)
                rdp_info("fast reconnect grace expired after %.0fs; desktop released",
                         grace);
        } else {
            rdp_info("fast reconnect completed; original desktop ownership transferred");
        }
        _sessionState = RDPSessionStateDisconnected;
    }
    dispatch_semaphore_signal(_teardownSem);
    [self endWithError:nil];
}

- (void)disconnect {
    rdp_info("disconnecting %s", _address.UTF8String);
    /* The peer loop polls this state every <=50ms and exits when it sees
     * Disconnecting, after which teardown runs on the session queue. */
    @synchronized(self) {
        _explicitDisconnect = YES;
        _sessionState = RDPSessionStateDisconnecting;
        dispatch_semaphore_signal(_resumeSem);
    }
}

- (void)disconnectForReplacement {
    int fd = -1;
    rdp_info("disconnecting %s for session replacement", _address.UTF8String);
    @synchronized(self) {
        if (_sessionState == RDPSessionStateDisconnected) return;
        _explicitDisconnect = YES;
        _replacementDisconnect = YES;
        _sessionState = RDPSessionStateDisconnecting;
        fd = _fd;
        dispatch_semaphore_signal(_resumeSem);
    }
    /* A graceful peer Close can block behind a client that stopped reading.
     * Interrupt the socket first so the session queue reaches display teardown
     * promptly. The fd remains owned by the session and is closed there. */
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
}

- (BOOL)waitForTeardown:(NSTimeInterval)timeout {
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW,
                                             (int64_t)(timeout * NSEC_PER_SEC));
    long rc = dispatch_semaphore_wait(_teardownSem, deadline);
    if (rc != 0)
        rdp_error("timed out after %.0fs waiting for %s to release its display",
                  timeout, _address.UTF8String);
    return rc == 0;
}

- (void)teardown {
    rdp_verbose("tearing down session for %s", _address.UTF8String);
    [_cursor stop];
    [_capture stop];
    [_encoder stop];
    [_audio stop];
    /* All queued audio blocks must finish before the peer they reference is
     * destroyed. Video capture is already stopped, so they can drain promptly. */
    if (_audioSendQueue)
        dispatch_sync(_audioSendQueue, ^{});
    [_clipboard stop];

    /* A launchd reload is intentional, not a network interruption. Tell the
     * client at the RDP layer before destroying TLS so Windows App leaves the
     * old canvas immediately instead of waiting on its own transport timeout. */
    if (_explicitDisconnect && !_replacementDisconnect && _peer)
        (void)rdp_peer_close_gracefully(_peer,
                                        ERRINFO_RPC_INITIATED_DISCONNECT);

    [_displayControl stop];
    [_display destroy];

    @synchronized(self) {
        if (_peer) { rdp_peer_destroy(_peer); _peer = NULL; }
    }
    if (_fd >= 0) { close(_fd); _fd = -1; }

    _sessionState = RDPSessionStateDisconnected;
    rdp_info("session torn down for %s", _address.UTF8String);

    /* Signal anyone waiting on takeover that our display is now released. Done
     * here (on the session queue, after destroy) rather than via the main-queue
     * delegate hop below — the main run loop does not run in this daemon, so the
     * semaphore is the reliable cross-thread completion signal. */
    dispatch_semaphore_signal(_teardownSem);

    [self endWithError:nil];
}

- (void)endWithError:(NSError *)error {
    /* Notify on a background queue, NOT the main queue: this daemon's main thread
     * blocks in kevent() with no running main run loop, so a main-queue async
     * would never fire and the server would never remove this session. */
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        [self.delegate sessionDidEnd:self error:error];
    });
}

@end
