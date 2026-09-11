#import "display/ScreenCapture.h"
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <CoreVideo/CoreVideo.h>
#import <IOSurface/IOSurface.h>
#include <string.h>
#include <time.h>
#define RDP_LOG_COMPONENT "capture"
#include "logging/RDPLog.h"

/*
 * ScreenCaptureKit (SCStream) capture.
 *
 * Replaces CGDisplayStream, which is deprecated since macOS 14 and on macOS 26
 * (Tahoe) delivers ZERO frames — even with kCGDisplayStreamShowCursor and active
 * cursor movement — producing a black remote desktop. SCStream is the sanctioned
 * API: it hands us IOSurface-backed CMSampleBuffers we feed straight to the encoder.
 *
 * A heartbeat timer occasionally re-feeds one tile from the most recent surface.
 * It keeps clients that expect periodic GFX traffic alive without re-encoding the
 * entire desktop while nothing changed. Progressive is tile-based rather than a
 * hardware video encoder, so a full-surface heartbeat is emphatically not cheap.
 */

@interface ScreenCapture () <SCStreamOutput, SCStreamDelegate>
@property (nonatomic, assign) CGDirectDisplayID displayID;
@property (nonatomic, strong) SCStream *stream;
@property (nonatomic, assign) BOOL capturing;
@property (nonatomic, strong) dispatch_queue_t captureQueue;
/* Frame delivery (including the synchronous CPU Progressive encoder) must not
 * run on ScreenCaptureKit's sample queue. At high resolutions one encode can
 * take longer than the capture interval; doing it inline makes old sample
 * buffers queue up and latency grows without bound. The delivery queue encodes
 * one frame while captureQueue coalesces all newer samples into one latest frame. */
@property (nonatomic, strong) dispatch_queue_t deliveryQueue;
@property (nonatomic, assign) uint64_t frameCount;
@property (nonatomic, assign) uint32_t capW;
@property (nonatomic, assign) uint32_t capH;
@property (nonatomic, assign) uint32_t captureFPS;
@property (nonatomic, assign) uint32_t activeCaptureFPS;
@property (nonatomic, assign) uint32_t idleCaptureFPS;
@property (nonatomic, assign) uint32_t desiredCaptureFPS;
@property (nonatomic, assign) uint32_t adaptiveIdleAfterMS;
@property (nonatomic, assign) uint64_t activeUntilMS;
@property (nonatomic, assign) BOOL adaptiveFrameRateEnabled;
@property (nonatomic, assign) BOOL configurationUpdateInFlight;
@property (nonatomic, strong) SCStreamConfiguration *streamConfiguration;
@property (nonatomic, strong) dispatch_source_t adaptiveTimer;
@property (nonatomic, strong) dispatch_source_t adaptiveActivitySignal;
@property (nonatomic, assign) uint64_t adaptiveInputActivityCount;
@property (nonatomic, assign) uint64_t adaptiveVisualActivityCount;
@property (nonatomic, assign) uint64_t adaptivePromotionCount;
@property (nonatomic, assign) uint64_t adaptiveIdleCount;
@property (nonatomic, assign) uint64_t lastVisualCandidateMS;
/* Most recent IOSurface, retained (IOSurfaceIncrementUseCount + CFRetain) so the
 * heartbeat can re-feed it after SCStream goes idle on a static screen. */
@property (nonatomic, assign) IOSurfaceRef lastSurface;
@property (nonatomic, strong) dispatch_source_t heartbeat;
@property (nonatomic, assign) uint64_t lastHeartbeatFrameCount;
@property (nonatomic, assign) IOSurfaceRef pendingSurface;
@property (nonatomic, assign) ScreenCaptureDirtyRegion pendingDirtyRegion;
@property (nonatomic, assign) BOOL deliveryScheduled;
@property (nonatomic, assign) uint64_t coalescedFrameCount;
@property (nonatomic, assign) uint64_t metadataDirtyFrameCount;
@property (nonatomic, assign) uint64_t fallbackDirtyFrameCount;
@property (nonatomic, assign) uint64_t fullDirtyFrameCount;
@property (nonatomic, assign) uint64_t heartbeatFrameCount;
@property (nonatomic, assign) uint64_t metadataDirtyRectCount;
@property (nonatomic, assign) uint64_t collapsedDirtyRegionCount;
@end

static void RDPDirtyRegionClear(ScreenCaptureDirtyRegion *region) {
    if (region) memset(region, 0, sizeof(*region));
}

static CGRect RDPDirtyRegionBounds(const ScreenCaptureDirtyRegion *region) {
    if (!region || region->count == 0) return CGRectNull;
    CGRect bounds = region->rects[0];
    for (uint32_t i = 1; i < region->count; i++)
        bounds = CGRectUnion(bounds, region->rects[i]);
    return bounds;
}

/* Append one clipped rectangle while cheaply eliminating containment. If a
 * pathological frame exceeds the fixed limit, collapse once to the bounding
 * rectangle instead of allocating or dropping damage. */
static void RDPDirtyRegionAddRect(ScreenCaptureDirtyRegion *region,
                                  CGRect rect, CGRect surfaceBounds) {
    if (!region) return;
    rect = CGRectIntersection(rect, surfaceBounds);
    if (CGRectIsNull(rect) || CGRectIsEmpty(rect)) return;

    if (region->collapsedToBounds && region->count == 1) {
        region->rects[0] = CGRectUnion(region->rects[0], rect);
        return;
    }

    for (uint32_t i = 0; i < region->count; i++) {
        if (CGRectContainsRect(region->rects[i], rect))
            return;
        if (CGRectContainsRect(rect, region->rects[i])) {
            region->rects[i] = rect;
            return;
        }
    }

    if (region->count < SCREEN_CAPTURE_MAX_DIRTY_RECTS) {
        region->rects[region->count++] = rect;
        return;
    }

    CGRect bounds = CGRectUnion(RDPDirtyRegionBounds(region), rect);
    region->count = 1;
    region->rects[0] = bounds;
    region->collapsedToBounds = YES;
}

static void RDPDirtyRegionAddRegion(ScreenCaptureDirtyRegion *dst,
                                    const ScreenCaptureDirtyRegion *src,
                                    CGRect surfaceBounds) {
    if (!dst || !src) return;
    for (uint32_t i = 0; i < src->count; i++)
        RDPDirtyRegionAddRect(dst, src->rects[i], surfaceBounds);
    if (src->collapsedToBounds) dst->collapsedToBounds = YES;
}

static BOOL RDPRectFromFrameMetadata(id value, CGRect *rect) {
    if (!value || !rect) return NO;

    /* Older ScreenCaptureKit releases bridge dirty rectangles as NSValue,
     * while macOS 27 returns CoreGraphics dictionary representations. Accept
     * both so a metadata representation change cannot take down the daemon. */
    if ([value isKindOfClass:[NSValue class]] &&
        [value respondsToSelector:@selector(rectValue)]) {
        *rect = [(NSValue *)value rectValue];
        return YES;
    }

    if ([value isKindOfClass:[NSDictionary class]]) {
        return CGRectMakeWithDictionaryRepresentation(
            (__bridge CFDictionaryRef)(NSDictionary *)value, rect);
    }

    return NO;
}

static uint32_t RDPCaptureFrameRate(uint32_t width, uint32_t height) {
    const char *env = getenv("RDP_FRAME_RATE");
    if (env && *env) {
        char *end = NULL;
        unsigned long parsed = strtoul(env, &end, 10);
        if (end && *end == '\0' && parsed >= 8u && parsed <= 60u)
            return (uint32_t)parsed;
    }

    const uint64_t pixels = (uint64_t)width * (uint64_t)height;
    if (pixels <= 4000000ULL) return 60u;
    if (pixels <= 8500000ULL) return 30u;
    return 15u;
}

static uint64_t RDPMonotonicMS(void) {
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static BOOL RDPEnvFlagEnabled(const char *name, BOOL defaultValue) {
    const char *value = getenv(name);
    if (!value || !*value) return defaultValue;
    return strcmp(value, "0") != 0 && strcasecmp(value, "false") != 0 &&
           strcasecmp(value, "no") != 0;
}

static uint32_t RDPEnvUIntInRange(const char *name, uint32_t defaultValue,
                                  uint32_t minimum, uint32_t maximum) {
    const char *value = getenv(name);
    if (!value || !*value) return defaultValue;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (end && *end == '\0' && parsed >= minimum && parsed <= maximum)
        return (uint32_t)parsed;
    rdp_error("invalid %s='%s'; using %u", name, value, defaultValue);
    return defaultValue;
}

@implementation ScreenCapture

/* captureQueue only. Coalesce rate changes while ScreenCaptureKit is applying
 * the previous update so a quick idle -> input transition cannot apply stale
 * configuration after the interaction has already begun. */
- (void)applyDesiredCaptureRate {
    if (!_capturing || !_stream || !_streamConfiguration ||
        _configurationUpdateInFlight || _desiredCaptureFPS == 0 ||
        _desiredCaptureFPS == _captureFPS)
        return;

    uint32_t targetFPS = _desiredCaptureFPS;
    SCStreamConfiguration *cfg = [_streamConfiguration copy];
    cfg.minimumFrameInterval = CMTimeMake(1, targetFPS);
    _configurationUpdateInFlight = YES;
    __weak typeof(self) weak = self;
    [_stream updateConfiguration:cfg completionHandler:^(NSError *error) {
        dispatch_async(weak.captureQueue, ^{
            typeof(self) self_ = weak;
            if (!self_) return;
            self_.configurationUpdateInFlight = NO;
            if (!error && self_.capturing) {
                uint32_t priorFPS = self_.captureFPS;
                self_.streamConfiguration = cfg;
                self_.captureFPS = targetFPS;
                if (targetFPS > priorFPS)
                    self_.adaptivePromotionCount++;
                else
                    self_.adaptiveIdleCount++;
                rdp_info("adaptive capture: %u -> %u fps (%s)", priorFPS,
                         targetFPS,
                         targetFPS == self_.activeCaptureFPS
                             ? "interaction/visual activity" : "idle");
            } else if (error && self_.capturing) {
                rdp_error("SCStream adaptive rate update to %u fps failed: %s",
                          targetFPS,
                          error.localizedDescription.UTF8String ?: "unknown");
            }
            [self_ applyDesiredCaptureRate];
        });
    }];
}

/* captureQueue only. */
- (void)recordAdaptiveActivityAtMS:(uint64_t)nowMS input:(BOOL)isInput {
    if (!_adaptiveFrameRateEnabled || !_capturing) return;
    if (isInput)
        _adaptiveInputActivityCount++;
    else
        _adaptiveVisualActivityCount++;
    uint64_t deadline = nowMS + _adaptiveIdleAfterMS;
    if (deadline > _activeUntilMS) _activeUntilMS = deadline;
    _desiredCaptureFPS = _activeCaptureFPS;
    [self applyDesiredCaptureRate];
}

- (void)noteRemoteInputActivity {
    dispatch_source_t signal = _adaptiveActivitySignal;
    if (signal) dispatch_source_merge_data(signal, 1);
}

- (void)noteVisualActivity {
    dispatch_source_t signal = _adaptiveActivitySignal;
    if (signal) dispatch_source_merge_data(signal, 2);
}

- (void)setPreferredFrameRate:(uint32_t)framesPerSecond {
    if (framesPerSecond < 8u || framesPerSecond > 60u) return;
    dispatch_async(_captureQueue, ^{
        if (!self.capturing || self.activeCaptureFPS == framesPerSecond)
            return;
        self.activeCaptureFPS = framesPerSecond;
        if (!self.adaptiveFrameRateEnabled ||
            RDPMonotonicMS() < self.activeUntilMS)
            self.desiredCaptureFPS = framesPerSecond;
        else
            self.desiredCaptureFPS = MIN(self.idleCaptureFPS, framesPerSecond);
        [self applyDesiredCaptureRate];
    });
}

- (instancetype)initWithDisplayID:(CGDirectDisplayID)did {
    if ((self = [super init])) {
        _displayID    = did;
        _captureQueue = dispatch_queue_create("com.macosrdp.capture",
                                              DISPATCH_QUEUE_SERIAL);
        _deliveryQueue = dispatch_queue_create("com.macosrdp.frame-delivery",
                                               DISPATCH_QUEUE_SERIAL);
        RDPDirtyRegionClear(&_pendingDirtyRegion);
        /* DATA_OR coalesces a burst of mouse/keyboard PDUs into one wake-up.
         * Never enqueue one block per mouse move: a fast iPad gesture can
         * otherwise starve the very capture queue it is trying to accelerate. */
        _adaptiveActivitySignal = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_DATA_OR, 0, 0, _captureQueue);
        __weak typeof(self) weak = self;
        dispatch_source_set_event_handler(_adaptiveActivitySignal, ^{
            typeof(self) self_ = weak;
            if (!self_) return;
            unsigned long activity = dispatch_source_get_data(
                self_.adaptiveActivitySignal);
            uint64_t nowMS = RDPMonotonicMS();
            if (activity & 1u)
                [self_ recordAdaptiveActivityAtMS:nowMS input:YES];
            if (activity & 2u) {
                /* Require sustained visual motion, not one isolated large
                 * repaint. At 15 fps a video supplies the confirming sample in
                 * ~67 ms, while a notification flash no longer causes a full
                 * 15 -> 60 -> 15 configuration cycle. */
                uint64_t priorMS = self_.lastVisualCandidateMS;
                self_.lastVisualCandidateMS = nowMS;
                if (priorMS && nowMS >= priorMS && nowMS - priorMS <= 250u)
                    [self_ recordAdaptiveActivityAtMS:nowMS input:NO];
            }
        });
        dispatch_resume(_adaptiveActivitySignal);
    }
    return self;
}

static void RDPRetainSurface(IOSurfaceRef surface) {
    if (!surface) return;
    IOSurfaceIncrementUseCount(surface);
    CFRetain(surface);
}

static void RDPReleaseSurface(IOSurfaceRef surface) {
    if (!surface) return;
    IOSurfaceDecrementUseCount(surface);
    CFRelease(surface);
}

/* captureQueue only. Keep at most one not-yet-encoded surface. Damage from all
 * replaced surfaces is unioned so the Progressive codec still refreshes every
 * changed region even though it encodes the newest pixels only. */
- (void)enqueueSurfaceForDelivery:(IOSurfaceRef)surface
                       dirtyRegion:(const ScreenCaptureDirtyRegion *)dirtyRegion {
    if (!surface || !_capturing) return;

    RDPRetainSurface(surface);
    if (_pendingSurface) {
        RDPReleaseSurface(_pendingSurface);
        _coalescedFrameCount++;
    }
    _pendingSurface = surface;
    RDPDirtyRegionAddRegion(&_pendingDirtyRegion, dirtyRegion,
                            CGRectMake(0, 0, _capW, _capH));

    if (_deliveryScheduled) return;
    [self schedulePendingDelivery];
}

/* captureQueue only. Move the pending surface into one delivery job. When that
 * job completes, schedule the newest coalesced surface (if any), never a FIFO of
 * stale frames. */
- (void)schedulePendingDelivery {
    if (_deliveryScheduled || !_pendingSurface || !_capturing) return;

    IOSurfaceRef surface = _pendingSurface; /* already retained for this job */
    ScreenCaptureDirtyRegion dirtyRegion = _pendingDirtyRegion;
    if (dirtyRegion.count == 0)
        RDPDirtyRegionAddRect(&dirtyRegion, CGRectMake(0, 0, _capW, _capH),
                              CGRectMake(0, 0, _capW, _capH));
    _pendingSurface = NULL;
    RDPDirtyRegionClear(&_pendingDirtyRegion);
    _deliveryScheduled = YES;

    uint32_t width = _capW;
    uint32_t height = _capH;
    ScreenCaptureFrameBlock handler = self.frameHandler;
    __weak typeof(self) weak = self;
    dispatch_async(_deliveryQueue, ^{
        if (handler)
            handler(surface, width, height, &dirtyRegion);
        RDPReleaseSurface(surface);

        dispatch_async(weak.captureQueue, ^{
            typeof(self) self_ = weak;
            if (!self_) return;
            self_.deliveryScheduled = NO;
            if (self_.capturing && self_.pendingSurface)
                [self_ schedulePendingDelivery];
        });
    });
}

- (BOOL)isCapturing { return _capturing; }

- (void)setLastSurface:(IOSurfaceRef)surface {
    if (_lastSurface == surface) return;
    if (surface) { IOSurfaceIncrementUseCount(surface); CFRetain(surface); }
    if (_lastSurface) { IOSurfaceDecrementUseCount(_lastSurface); CFRelease(_lastSurface); }
    _lastSurface = surface;
}

- (BOOL)startWithWidth:(uint32_t)width height:(uint32_t)height {
    if (_capturing) return YES;
    _capW = width; _capH = height;
    rdp_verbose("starting SCStream on displayID=%u %ux%u", _displayID, width, height);

    /* Screen Recording must be granted (same TCC service SCStream uses). In the GUI
     * session this pops the prompt the first time and registers the binary. */
    if (!CGPreflightScreenCaptureAccess()) {
        rdp_error("Screen Recording not granted — requesting access (grant the prompt, "
                  "or System Settings > Privacy & Security > Screen Recording, then reconnect)");
        CGRequestScreenCaptureAccess();
    }

    _capturing = YES;

    __weak typeof(self) weak = self;
    /* SCShareableContent enumeration is async — set up the stream in its callback. */
    [SCShareableContent getShareableContentWithCompletionHandler:^(SCShareableContent *content,
                                                                   NSError *error) {
        typeof(self) self_ = weak;
        if (!self_ || !self_.capturing) return;
        if (error || !content) {
            rdp_error("SCShareableContent failed: %s",
                      error.localizedDescription.UTF8String ?: "unknown");
            return;
        }

        SCDisplay *target = nil;
        for (SCDisplay *d in content.displays) {
            if (d.displayID == self_.displayID) { target = d; break; }
        }
        if (!target) target = content.displays.firstObject;
        if (!target) { rdp_error("no SCDisplay available for capture"); return; }

        SCContentFilter *filter =
            [[SCContentFilter alloc] initWithDisplay:target excludingWindows:@[]];

        SCStreamConfiguration *cfg = [[SCStreamConfiguration alloc] init];
        cfg.width                = width;
        cfg.height               = height;
        cfg.pixelFormat          = kCVPixelFormatType_32BGRA;
        /* Use 60 Hz for iPad-sized desktops, then scale down with pixel count.
         * Delivery remains latest-frame-only, so a temporary encode spike drops
         * stale captures instead of growing latency. RDP_FRAME_RATE=8..60
         * overrides the resolution-aware default for controlled A/B tests. */
        uint64_t pixels = (uint64_t)width * (uint64_t)height;
        uint32_t captureFPS = RDPCaptureFrameRate(width, height);
        self_.activeCaptureFPS = captureFPS;
        self_.adaptiveFrameRateEnabled =
            RDPEnvFlagEnabled("RDP_ADAPTIVE_FRAME_RATE", NO);
        uint32_t defaultIdleFPS = MIN(15u, captureFPS);
        self_.idleCaptureFPS = RDPEnvUIntInRange(
            "RDP_IDLE_FRAME_RATE", defaultIdleFPS, 2u, captureFPS);
        self_.adaptiveIdleAfterMS = RDPEnvUIntInRange(
            "RDP_IDLE_AFTER_MS", 2000u, 250u, 10000u);
        self_.desiredCaptureFPS = captureFPS;
        self_.activeUntilMS = RDPMonotonicMS() + self_.adaptiveIdleAfterMS;
        self_.captureFPS = captureFPS;
        cfg.minimumFrameInterval = CMTimeMake(1, captureFPS);
        cfg.queueDepth           = 2;
        rdp_info("capture pacing: %d fps, latest-frame coalescing ON (%llu pixels); "
                 "adaptive=%s idle=%u fps after %u ms",
                 captureFPS, (unsigned long long)pixels,
                 self_.adaptiveFrameRateEnabled ? "ON" : "OFF",
                 self_.idleCaptureFPS, self_.adaptiveIdleAfterMS);
        /* Show the macOS cursor composited into the capture by default, so the user
         * sees the real Mac pointer (I-beam, resize, beachball, etc.). Configurable
         * via RDP_SHOW_CURSOR=0 to hide it (e.g. if the client's own cursor is
         * preferred and the double-cursor is distracting). A GUI config tool can set
         * this env var in the LaunchAgent. */
        /* Default to the client-drawn cursor (responsive). Compositing the Mac
         * cursor into the video (RDP_SHOW_CURSOR=1) shows the real pointer shapes
         * but lags badly — every move round-trips through encode/network/decode.
         * (Lag-free Mac cursor needs RDP pointer-update PDUs — a planned follow-up.) */
        const char *showCur = getenv("RDP_SHOW_CURSOR");
        cfg.showsCursor          = (showCur && showCur[0] == '1') ? YES : NO;

        SCStream *stream = [[SCStream alloc] initWithFilter:filter
                                              configuration:cfg
                                                   delegate:self_];
        NSError *addErr = nil;
        if (![stream addStreamOutput:self_ type:SCStreamOutputTypeScreen
                  sampleHandlerQueue:self_.captureQueue error:&addErr]) {
            rdp_error("SCStream addStreamOutput failed: %s",
                      addErr.localizedDescription.UTF8String ?: "unknown");
            return;
        }
        self_.stream = stream;
        self_.streamConfiguration = cfg;

        [stream startCaptureWithCompletionHandler:^(NSError *startErr) {
            if (startErr) {
                rdp_error("SCStream startCapture failed: %s",
                          startErr.localizedDescription.UTF8String ?: "unknown");
                return;
            }
            rdp_info("capture started (SCStream) on displayID=%u", self_.displayID);
        }];

        /* Heartbeat: one Progressive tile every two seconds is enough to keep GFX
         * traffic alive. The old 250 ms full-screen heartbeat compressed roughly
         * 810 RemoteFX tiles even on a static 2252x1473 desktop, consuming a core
         * and filling the DVC/TCP buffers with disposable frames. */
        dispatch_source_t hb = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,
                                                      0, 0, self_.captureQueue);
        dispatch_source_set_timer(hb, dispatch_time(DISPATCH_TIME_NOW, 0),
                                  (uint64_t)(NSEC_PER_SEC * 2), NSEC_PER_SEC / 4);
        dispatch_source_set_event_handler(hb, ^{
            typeof(self) s2 = weak;
            if (!s2 || !s2.capturing) return;
            /* Coalesce with SCStream: if it delivered a frame since the last tick the
             * stream is active, so skip — otherwise we'd double the frame rate and
             * flood the client (which dropped us with an "invalid format" decode error
             * under ~110fps). The heartbeat only re-feeds when the screen is idle. */
            if (s2.frameCount != s2.lastHeartbeatFrameCount) {
                s2.lastHeartbeatFrameCount = s2.frameCount;
                return;
            }
            IOSurfaceRef surf = s2.lastSurface;
            if (surf) {
                ScreenCaptureDirtyRegion region = {0};
                RDPDirtyRegionAddRect(&region, CGRectMake(0, 0, 1, 1),
                                      CGRectMake(0, 0, s2.capW, s2.capH));
                s2.heartbeatFrameCount++;
                [s2 enqueueSurfaceForDelivery:surf
                                  dirtyRegion:&region];
            }
        });
        self_.heartbeat = hb;
        dispatch_resume(hb);

        if (self_.adaptiveFrameRateEnabled && self_.idleCaptureFPS < captureFPS) {
            dispatch_source_t adaptive = dispatch_source_create(
                DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self_.captureQueue);
            dispatch_source_set_timer(
                adaptive,
                dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                250 * NSEC_PER_MSEC, 25 * NSEC_PER_MSEC);
            dispatch_source_set_event_handler(adaptive, ^{
                typeof(self) s2 = weak;
                if (!s2 || !s2.capturing) return;
                uint64_t nowMS = RDPMonotonicMS();
                uint32_t wanted = nowMS < s2.activeUntilMS
                    ? s2.activeCaptureFPS : s2.idleCaptureFPS;
                if (wanted != s2.desiredCaptureFPS) {
                    s2.desiredCaptureFPS = wanted;
                    [s2 applyDesiredCaptureRate];
                }
            });
            self_.adaptiveTimer = adaptive;
            dispatch_resume(adaptive);
        }
    }];

    return YES;
}

/* SCStreamOutput */
- (void)stream:(SCStream *)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
                   ofType:(SCStreamOutputType)type {
    if (type != SCStreamOutputTypeScreen) return;
    if (!sampleBuffer || !CMSampleBufferIsValid(sampleBuffer)) return;

    /* Only act on complete/started frames; idle/blank carry no fresh surface. */
    ScreenCaptureDirtyRegion dirtyRegion = {0};
    CGRect surfaceBounds = CGRectMake(0, 0, self.capW, self.capH);
    BOOL usedMetadataDirtyRect = NO;
    CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, false);
    if (attachments && CFArrayGetCount(attachments) > 0) {
        CFDictionaryRef att = (CFDictionaryRef)CFArrayGetValueAtIndex(attachments, 0);
        CFNumberRef statusRef =
            (CFNumberRef)CFDictionaryGetValue(att, (__bridge CFStringRef)SCStreamFrameInfoStatus);
        int status = -1;
        if (statusRef) CFNumberGetValue(statusRef, kCFNumberIntType, &status);
        if (status != SCFrameStatusComplete && status != SCFrameStatusStarted)
            return;

        /* ScreenCaptureKit reports damage in surface pixels. Preserve its union
         * instead of treating every callback as a full-screen redraw; this is
         * especially important for the CPU Progressive fallback. */
        NSArray *dirtyRects = (__bridge NSArray *)
            CFDictionaryGetValue(att, (__bridge CFStringRef)SCStreamFrameInfoDirtyRects);
        if ([dirtyRects isKindOfClass:[NSArray class]] && dirtyRects.count > 0) {
            for (id value in dirtyRects) {
                CGRect rect = CGRectZero;
                if (!RDPRectFromFrameMetadata(value, &rect))
                    continue;
                uint32_t before = dirtyRegion.count;
                RDPDirtyRegionAddRect(&dirtyRegion, rect, surfaceBounds);
                if (dirtyRegion.count != before)
                    self.metadataDirtyRectCount++;
            }
            if (dirtyRegion.count > 0) {
                usedMetadataDirtyRect = YES;
            }
        }
    }

    if (dirtyRegion.count == 0)
        RDPDirtyRegionAddRect(&dirtyRegion, surfaceBounds, surfaceBounds);
    if (dirtyRegion.collapsedToBounds)
        self.collapsedDirtyRegionCount++;

    CVImageBufferRef pixbuf = CMSampleBufferGetImageBuffer(sampleBuffer);
    if (!pixbuf) return;
    IOSurfaceRef surface = CVPixelBufferGetIOSurface(pixbuf);
    if (!surface) return;

    self.lastSurface = surface;          /* retains; releases previous */
    self.frameCount++;
    if (usedMetadataDirtyRect)
        self.metadataDirtyFrameCount++;
    else
        self.fallbackDirtyFrameCount++;
    CGRect dirtyBounds = RDPDirtyRegionBounds(&dirtyRegion);
    if (dirtyRegion.count == 1 && dirtyBounds.origin.x <= 0 &&
        dirtyBounds.origin.y <= 0 && dirtyBounds.size.width >= self.capW &&
        dirtyBounds.size.height >= self.capH)
        self.fullDirtyFrameCount++;
    uint64_t statsCadence = (uint64_t)(self.captureFPS ? self.captureFPS : 30u) * 10u;
    if (self.frameCount % statsCadence == 0)
        rdp_info("capture stats: frames=%llu fps=%u metadata=%llu rects=%llu "
                 "fallback-full=%llu full-dirty=%llu collapsed=%llu "
                 "coalesced=%llu heartbeat=%llu adaptive=%llu/%llu/%llu/%llu",
                 (unsigned long long)self.frameCount,
                 self.captureFPS,
                 (unsigned long long)self.metadataDirtyFrameCount,
                 (unsigned long long)self.metadataDirtyRectCount,
                 (unsigned long long)self.fallbackDirtyFrameCount,
                 (unsigned long long)self.fullDirtyFrameCount,
                 (unsigned long long)self.collapsedDirtyRegionCount,
                 (unsigned long long)self.coalescedFrameCount,
                 (unsigned long long)self.heartbeatFrameCount,
                 (unsigned long long)self.adaptiveInputActivityCount,
                 (unsigned long long)self.adaptiveVisualActivityCount,
                 (unsigned long long)self.adaptivePromotionCount,
                 (unsigned long long)self.adaptiveIdleCount);

    [self enqueueSurfaceForDelivery:surface dirtyRegion:&dirtyRegion];
}

/* SCStreamDelegate */
- (void)stream:(SCStream *)stream didStopWithError:(NSError *)error {
    rdp_verbose("SCStream stopped: %s",
                error.localizedDescription.UTF8String ?: "(no error)");
}

- (void)stop {
    if (!_capturing) return;
    rdp_verbose("stopping capture after %llu frames", (unsigned long long)_frameCount);
    _capturing = NO;

    if (_heartbeat) { dispatch_source_cancel(_heartbeat); _heartbeat = nil; }
    if (_adaptiveTimer) {
        dispatch_source_cancel(_adaptiveTimer);
        _adaptiveTimer = nil;
    }
    if (_adaptiveActivitySignal)
        dispatch_source_cancel(_adaptiveActivitySignal);
    if (_stream) {
        [_stream stopCaptureWithCompletionHandler:^(NSError *e) { (void)e; }];
        _stream = nil;
    }
    _streamConfiguration = nil;
    /* Cancel any queued latest frame and wait for the one in-flight encoder job.
     * RDPSession destroys the peer after this method returns, so draining here
     * prevents a late frame from dereferencing a freed peer. */
    dispatch_sync(_captureQueue, ^{
        if (self.pendingSurface) {
            RDPReleaseSurface(self.pendingSurface);
            self.pendingSurface = NULL;
        }
        RDPDirtyRegionClear(&self->_pendingDirtyRegion);
        self.lastSurface = NULL;  /* releases */
    });
    dispatch_sync(_deliveryQueue, ^{});
    if (_coalescedFrameCount)
        rdp_info("capture backpressure: coalesced %llu stale frame(s)",
                 (unsigned long long)_coalescedFrameCount);
}

- (void)dealloc { [self stop]; }

@end
