#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <IOSurface/IOSurface.h>

#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/server/rdpgfx.h>
#include <freerdp/server/disp.h>
#include <freerdp/server/cliprdr.h>
#include <freerdp/server/rdpsnd.h>
#include <freerdp/codec/region.h>
#include <freerdp/channels/wtsvc.h>
#include <winpr/wtsapi.h>

#include "protocol/RDPTCPLatency.h"
#include "protocol/RDPProgressiveQuality.h"

typedef struct rdp_peer_context RDPPeerContext;
typedef struct RDPWebDAVServer  RDPWebDAVServer;

typedef enum {
    RDPGraphicsModeUnknown = 0,
    RDPGraphicsModeAVC420,
    RDPGraphicsModeProgressive,
} RDPGraphicsMode;

typedef void (*RDPPeerInputCallback)(void *userdata, uint16_t flags, uint16_t code);
typedef void (*RDPPeerUnicodeInputCallback)(void *userdata, uint16_t flags,
                                            uint16_t codeUnit);
typedef void (*RDPPeerKeyboardResetCallback)(void *userdata);
typedef void (*RDPPeerMouseCallback)(void *userdata, uint16_t flags, uint16_t x, uint16_t y);
typedef void (*RDPPeerClipboardCallback)(void *userdata, const uint8_t *data, size_t len, uint32_t format);
typedef bool (*RDPPeerClipboardFilesCallback)(void *userdata,
                                              const char *const *paths,
                                              size_t count);
typedef void (*RDPPeerReadyCallback)(void *userdata, uint32_t width, uint32_t height, uint32_t colorDepth);
typedef bool (*RDPPeerDisplayResizeCallback)(void *userdata, uint32_t width,
                                             uint32_t height);
typedef void (*RDPPeerKeyframeCallback)(void *userdata);
typedef bool (*RDPPeerMultitransportBootstrapCallback)(
    void *userdata, uint32_t requestID, const uint8_t securityCookie[16]);
typedef bool (*RDPPeerDVCTunnelSendCallback)(void *userdata,
                                             const uint8_t *data, size_t len);
typedef void (*RDPPeerFrameRateCallback)(void *userdata, uint32_t framesPerSecond);

typedef struct {
    uint64_t observedAtMS;
    uint64_t retransmissions;
    uint64_t lossEvents;
    uint32_t smoothedRTTMS;
    uint32_t inflightPackets;
    uint32_t congestionWindowPackets;
    uint32_t queuedBytes;
} RDPPeerUDPTransportMetrics;

/* IRP async completion callback type.  Invoked on the peer run-loop thread
 * when a PAKID_CORE_DEVICE_IOCOMPLETION arrives for the matching CompletionId.
 * ioStatus — NT status code (0 = success).
 * payload/payloadLen — bytes following the 12-byte completion header (may be 0).
 * userdata — opaque pointer supplied to rdpdr_alloc_request. */
typedef void (*RDPIrpCallback)(uint32_t ioStatus,
                               const uint8_t *payload, uint32_t payloadLen,
                               void *userdata);

typedef struct {
    RDPPeerInputCallback     onKeyboard;
    RDPPeerUnicodeInputCallback onUnicodeKeyboard;
    RDPPeerKeyboardResetCallback onKeyboardReset;
    RDPPeerMouseCallback     onMouse;
    RDPPeerMouseCallback     onMouseEx;
    RDPPeerClipboardCallback onClipboard;
    RDPPeerClipboardFilesCallback onClipboardFiles;
    RDPPeerReadyCallback     onReady;
    /* Runs on the peer/session loop after the Display Control channel has
     * delivered a complete monitor layout. The callback must synchronously
     * resize the retained macOS display and rebuild capture/input for the new
     * dimensions; returning false rejects the client request. */
    RDPPeerDisplayResizeCallback onDisplayResize;
    /* Asks the encoder to emit an IDR keyframe ASAP. Invoked when the GFX channel
     * becomes ready (frames encoded earlier were discarded, so the first sent
     * frame must be a keyframe) or when a delta arrives before any keyframe. */
    RDPPeerKeyframeCallback  onKeyframeRequest;
    RDPPeerMultitransportBootstrapCallback onMultitransportBootstrap;
    RDPPeerDVCTunnelSendCallback onDVCTunnelSend;
    RDPPeerFrameRateCallback onFrameRateChange;
    bool allowMultitransport;
    void *userdata;
} RDPPeerCallbacks;

/* Maximum number of redirected drives we track simultaneously. */
#define RDPDR_MAX_DEVICES 8
#define RDP_POINTER_CACHE_TRACKED 32
#define RDP_QOE_SEND_HISTORY 128

struct rdp_peer_context {
    rdpContext          base;       /* MUST be first */
    RDPPeerCallbacks    callbacks;
    HANDLE              vcm;        /* WTSOpenServerA handle — owns gfx/cliprdr/rdpsnd */
    RdpgfxServerContext *gfx;
    DispServerContext   *disp;
    CliprdrServerContext *cliprdr;
    RdpsndServerContext  *rdpsnd;
    uint32_t             surfaceId;
    uint32_t             frameId;    /* monotonic GFX frame id for StartFrame/EndFrame */
    /* RDPGFX frame acknowledgements are the latency/backpressure signal. The
     * GFX pump updates these on the peer thread while the capture delivery
     * queue reads them before encoding, so they must be atomic. */
    _Atomic uint32_t     lastAckFrameId;
    _Atomic uint32_t     clientQueueDepth;
    _Atomic uint32_t     lastAckTotalFramesDecoded;
    _Atomic uint64_t     lastAckTimestampMS;
    /* Latest end-to-end graphics response received from the client (ordinary
     * frame ACK or QoE render ACK). Used to expire iPadOS-backgrounded sessions
     * whose TCP socket remains open even though the RDP client stopped reading. */
    _Atomic uint64_t     lastClientResponseMS;
    _Atomic uint32_t     lastQoeFrameId;
    _Atomic uint32_t     lastQoeClientTimestampMS;
    _Atomic uint16_t     lastQoeDecodeSpanMS;
    _Atomic uint16_t     lastQoeRenderMS;
    _Atomic uint32_t     lastQoeFeedbackMS;
    _Atomic uint64_t     qoeAckCount;
    /* Send timestamps keyed by frame ID let a QoE ACK measure the complete
     * server-submit -> client-render -> server-feedback loop. This is the only
     * signal that crosses FRP's internal buffers; local socket writability does
     * not. The frame ID is the release/acquire publication word for each slot. */
    _Atomic uint64_t     qoeSendTimesMS[RDP_QOE_SEND_HISTORY];
    _Atomic uint32_t     qoeSendSizes[RDP_QOE_SEND_HISTORY];
    _Atomic uint32_t     qoeSendFrameIds[RDP_QOE_SEND_HISTORY];
    _Atomic bool         gfxAckSeen;
    _Atomic bool         gfxAckSuspended;
    _Atomic uint64_t     progressiveAckDrops;
    _Atomic uint64_t     progressiveQoeDrops;
    _Atomic uint64_t     progressiveBusyDrops;
    _Atomic uint64_t     progressivePacingDrops;
    _Atomic uint64_t     progressiveTransportDrops;
    _Atomic uint64_t     transportDrainAttempts;
    _Atomic uint64_t     transportDrainStillBlocked;
    _Atomic uint64_t     transportDrainErrors;
    _Atomic bool         transportWriteBlocked;
    _Atomic uint32_t     progressiveTargetBytesPerSec;
    _Atomic uint32_t     progressiveBaseRTTMS;
    _Atomic uint32_t     progressiveLastFrameBytes;
    _Atomic uint32_t     progressiveLastFrameTiles;
    uint32_t             progressiveMaxBytesPerSec;
    uint32_t             progressiveMinBytesPerSec;
    _Atomic uint32_t     progressiveFrameRate;
    _Atomic uint32_t     progressiveFrameIntervalMS;
    uint32_t             progressiveBaseFrameRate;
    uint32_t             progressiveMaxFrameRate;
    uint32_t             fpsHealthyFeedbackCount;
    uint32_t             fpsUnhealthyFeedbackCount;
    uint32_t             progressiveMaxQoeInflight;
    uint32_t             clientLivenessTimeoutMS;
    RDPTCPLatencyController tcpLatency;
    RDPProgressiveQualityController progressiveQuality;
    uint64_t             progressiveNextSendMS;
    /* Damage from capture frames intentionally skipped by ACK/transport
     * backpressure. The next frame sent must cover their union so the client's
     * persistent Progressive surface never retains stale tiles. Capture delivery
     * is serial, therefore these bounds do not require atomics. */
    REGION16             progressivePendingRegion;
    bool                 progressivePendingRegionInitialized;
    /* Last pixel state successfully submitted to the client. ScreenCaptureKit
     * can mark a whole GPU-backed window dirty for a tiny animation; comparing
     * 64x64 tiles against this compact BGRA reference removes those false dirty
     * tiles before RemoteFX compression. */
    uint8_t             *progressiveReferencePixels;
    uint8_t             *progressiveTileMask;
    /* Tiles last sent while motion quantization was active. A return to full
     * quality refreshes only this set instead of retransmitting the desktop. */
    uint8_t             *progressiveLowQualityTiles;
    size_t               progressiveReferenceSize;
    uint32_t             progressiveReferenceStride;
    uint32_t             progressiveTileColumns;
    uint32_t             progressiveTileRows;
    uint32_t             progressiveRefineMaxTiles;
    uint32_t             progressiveRefinementCursor;
    uint64_t             progressiveRefinementBatches;
    bool                 progressiveReferenceValid;
    uint64_t             progressiveUnchangedFrames;
    /* Serializes ALL writes to the single RDP transport (TLS socket). FreeRDP is
     * NOT thread-safe for concurrent sends: the encoder thread (GFX SurfaceCommand),
     * the run-loop thread (CheckFileDescriptor + VCM pump + GFX handle_messages),
     * the clipboard poll thread (cliprdr ServerFormatList) and the audio thread
     * (rdpsnd SendSamples) all write the same socket. Unsynchronized, their bytes
     * interleave and the GFX bytestream desyncs -> mstsc decodes a "packet of type
     * Unknown" and drops the session (Reason 3334). Every transport write MUST hold
     * this lock. RECURSIVE so a run-loop callback (e.g. cliprdr) can re-enter while
     * the loop already holds it. */
    pthread_mutex_t      xportLock;
    bool                 gfxOpened;  /* GFX DVC Open() succeeded (drdynvc ready) */
    bool                 dispOpened; /* MS-RDPEDISP DVC opened and caps sent */
    bool                 gfxReady;   /* client sent GFX caps; surface mapped */
    uint32_t             gfxChannelId;
    _Atomic bool         udpTunnelReady;
    _Atomic uint64_t     udpStatsObservedAtMS;
    _Atomic uint64_t     udpRetransmissions;
    _Atomic uint64_t     udpLossEvents;
    _Atomic uint64_t     udpLastCongestionMS;
    _Atomic uint32_t     udpSmoothedRTTMS;
    _Atomic uint32_t     udpInflightPackets;
    _Atomic uint32_t     udpCongestionWindowPackets;
    _Atomic uint32_t     udpQueuedBytes;
    bool                 udpSoftSyncRequested;
    bool                 udpSoftSyncActive;
    bool                 sentKeyframe;     /* a keyframe has been sent this session */
    bool                 keyframeRequested;/* debounce: requested an IDR, awaiting it */
    bool                 outputSuppressed; /* client minimized: Suppress Output PDU -> pause sends */
    uint64_t             outputSuppressedSinceMS; /* bound a missing restore PDU */
    bool                 outputResumeProbeAttempted; /* one compatibility repaint per background cycle */
    _Atomic bool         pendingGraphicsResync; /* rebuild only the client RDPGFX surface */
    bool                 activated;
    /* Latest RDPEDISP request is atomically replaced when the client resizes
     * repeatedly. Packed as width<<32 | height and consumed by the peer loop. */
    _Atomic uint64_t     pendingDisplaySize;
    /* Standard MS-RDPBCGR auto-reconnect state. incomingReconnectCookie is the
     * proof supplied by this connection; expectedReconnectCookie is the newly
     * generated proof retained by the desktop for its next network reconnect. */
    ARC_CS_PRIVATE_PACKET incomingReconnectCookie;
    ARC_CS_PRIVATE_PACKET expectedReconnectCookie;
    bool                 incomingReconnectCookieValid;
    bool                 expectedReconnectCookieValid;
    /* Connect-time MS-RDPBCGR network-characteristics exchange. The bandwidth
     * probe grows from 1 to 4 to 16 payloads when the preceding response was
     * quick enough, then several sequential RTT samples are averaged. */
    uint8_t              networkDetectPhase;
    uint8_t              networkDetectRTTCount;
    uint64_t             networkDetectBandwidthStartMS;
    uint64_t             networkDetectRTTSumMS;
    uint32_t             networkDetectResponseLatencyMS;
    uint32_t             networkDetectTimeDeltaMS;
    uint32_t             networkDetectByteCount;
    /* Pointer image cache mirrored on the Windows client. Reusing cache slot 0
     * for every differently-sized shape made some Windows App builds combine
     * stale dimensions/masks during rapid cursor changes. Give every unique
     * shape a stable slot and select it with PointerCached on repeat visits. */
    struct {
        uint64_t hash;
        uint16_t width;
        uint16_t height;
        uint16_t hotX;
        uint16_t hotY;
        bool     valid;
    } pointerCache[RDP_POINTER_CACHE_TRACKED];
    uint16_t             pointerCacheNext;
    RDPGraphicsMode      graphicsMode;
    void                *progressiveCodec; /* PROGRESSIVE_CONTEXT*, kept opaque here */
    uint32_t             surfaceWidth;
    uint32_t             surfaceHeight;
    bool                 audioReady; /* set by rdpsnd Activated callback */
    /* Clipboard: the host's current data, advertised via Format List and held
     * until the client sends a Format Data Request (MS-RDPECLIP flow). Owned
     * copy — the source pasteboard pointer is only valid during the send call. */
    uint8_t             *clipData;
    size_t               clipLen;
    uint32_t             clipFormat;
    /* File clipboard (Mac -> client): clipData contains the serialized
     * FileGroupDescriptorW list while these arrays retain the corresponding
     * local paths and advertised sizes for later range requests. */
    char                **clipFilePaths;
    uint64_t             *clipFileSizes;
    uint32_t              clipFileCount;
    /* The format id we asked the client for via ServerFormatDataRequest after it
     * advertised a Format List (Win->Mac paste). The matching ClientFormatDataResponse
     * carries no format id of its own, so we remember what we requested. */
    uint32_t             clipReqFormat;
    bool                 clipReqIsFileList;
    /* File clipboard (client -> Mac): remote files are pulled sequentially into
     * a private flat staging directory. Only after every advertised byte has
     * arrived are the paths published to the macOS pasteboard. */
    char                *clipIncomingStagingDir;
    char               **clipIncomingPaths;
    uint64_t            *clipIncomingSizes;
    uint32_t             clipIncomingCount;
    uint32_t             clipIncomingIndex;
    uint64_t             clipIncomingOffset;
    uint32_t             clipIncomingExpectedStreamId;
    uint32_t             clipIncomingRequestedBytes;
    uint32_t             clipIncomingNextStreamId;
    int                  clipIncomingFD;
    bool                 clipIncomingActive;
    bool                 clipIncomingPublished;
    /* RDPDR (MS-RDPEFS) drive-redirection static VC. Non-NULL only when
     * RDP_RDPDR_ENABLED=1. Raw WTS channel; protocol state machine runs in C. */
    HANDLE               rdpdrChannel;   /* WTSVirtualChannelOpen handle */
    HANDLE               rdpdrEvent;     /* WTSVirtualEventHandle for the run loop */
    int                  rdpdrState;     /* RdpdrHandshakeState enum (int for C compat) */
    uint16_t             rdpdrClientId;  /* client-assigned id from ANNOUNCE_REPLY */
    uint32_t             rdpdrNextReqId; /* monotonic IRP request id counter */
    /* Pending IRP request table — up to RDPDR_MAX_PENDING in-flight requests.
     * Each slot carries an optional async callback + userdata so callers on
     * other threads (WebDAV handlers) can be woken when the completion arrives. */
#define RDPDR_MAX_PENDING 64
    struct {
        uint32_t       requestId;  /* 0 = slot free */
        uint32_t       deviceId;
        char           path[64];   /* requested path, for logging */
        RDPIrpCallback callback;   /* NULL = fire-and-forget */
        void          *userdata;
    } rdpdrPending[RDPDR_MAX_PENDING];
    /* WebDAV servers — one per redirected drive (RDPDR_MAX_DEVICES slots).
     * Created in DEVICE_LIST_ANNOUNCE; destroyed in context_free. */
    RDPWebDAVServer     *webdavServers[RDPDR_MAX_DEVICES];
    /* cliprdr handshake complete (client sent its Capabilities/Format List). The
     * Mac->Win advertise (ServerFormatList, called from the clipboard POLL thread)
     * MUST NOT run before this — sending a Format List before the channel's send
     * state is initialized corrupts FreeRDP's cliprdr stream and aborts the daemon
     * (WinPR Stream_Write_UINT32 assert). Set true in the client caps/format-list
     * callbacks; gates rdp_peer_send_clipboard. */
    bool                 clipReady;
    /* AUDIO_INPUT (MS-RDPEAI) mic-redirection channel. Non-NULL only when
     * RDP_AUDIO_INPUT=1. Stored as void* so this C header stays ObjC-free;
     * RDPPeer.c casts it through __bridge when handing it to AudioInput.m.
     * ARC ownership is maintained by the ObjC object itself; the void* here is
     * a non-owning reference — lifetime is managed by context_free calling
     * rdp_peer_close_audio_input(), which releases the ObjC object. */
    void                *audioInput;   /* __strong RDPAudioInput * under ARC */
};

freerdp_peer *rdp_peer_create(int fd, const RDPPeerCallbacks *callbacks);
void          rdp_peer_destroy(freerdp_peer *peer);
/* Send the standard server-initiated RDP disconnect sequence (Deactivate All,
 * Set Error Info when negotiated, and MCS Disconnect Provider Ultimatum).
 * The caller still owns and must destroy the peer afterwards. */
bool          rdp_peer_close_gracefully(freerdp_peer *peer,
                                        uint32_t errorInfo);
bool          rdp_peer_run_once(freerdp_peer *peer);
void          rdp_peer_set_udp_tunnel_ready(freerdp_peer *peer, bool ready);
void          rdp_peer_update_udp_transport_metrics(
                  freerdp_peer *peer,
                  const RDPPeerUDPTransportMetrics *metrics);
bool          rdp_peer_is_udp_soft_sync_active(freerdp_peer *peer);
bool          rdp_peer_receive_udp_dvc(freerdp_peer *peer,
                                       const uint8_t *data, size_t len);

bool rdp_peer_get_incoming_reconnect_cookie(freerdp_peer *peer,
                                            ARC_CS_PRIVATE_PACKET *cookie);
bool rdp_peer_get_expected_reconnect_cookie(freerdp_peer *peer,
                                            ARC_CS_PRIVATE_PACKET *cookie);
bool rdp_peer_disconnect_is_reconnectable(freerdp_peer *peer);

/* Read the logon credentials the client supplied in the RDP info packet (valid
 * once the peer has activated — i.e. inside/after the onReady callback). The
 * out-pointers receive pointers OWNED by the FreeRDP peer settings (do not free;
 * valid for the peer's lifetime). Any out value may be NULL if the client sent
 * none. Pass NULL for fields you don't need. NEVER log the returned password. */
void rdp_peer_get_credentials(freerdp_peer *peer,
                              const char **username,
                              const char **password,
                              const char **domain);

/*
 * Send an AVC420 (H.264) frame.
 *
 * The H.264 bitstream always encodes the full surface (VideoToolbox encodes
 * the whole IOSurface), so the surface-command destination is always the full
 * surface. The damage region is signalled via the AVC420 metablock regionRects:
 *   - keyframe  -> region = full surface (entire picture is fresh)
 *   - interframe-> region = dirty rect   (only changed pixels need compositing)
 *
 * A valid quantQualityVals array (one entry per region) is ALWAYS supplied —
 * the FreeRDP server serializer dereferences it unconditionally, so a NULL
 * here is a guaranteed crash on the first frame.
 *
 * dirtyX/Y/W/H are in surface pixels; ignored when isKeyFrame is true.
 */
bool rdp_peer_send_h264_frame(freerdp_peer *peer,
                               const uint8_t *data, size_t len,
                               uint32_t width, uint32_t height,
                               bool isKeyFrame,
                               uint16_t dirtyX, uint16_t dirtyY,
                               uint16_t dirtyW, uint16_t dirtyH);

/* Negotiated graphics mode. In force-avc mode this reports AVC420 even when
 * the client advertised AVC_DISABLED; that mode exists solely for an isolated
 * compatibility probe and is never selected by the default auto policy. */
RDPGraphicsMode rdp_peer_graphics_mode(freerdp_peer *peer);

/* CPU RemoteFX Progressive fallback for clients that explicitly disable AVC.
 * The IOSurface is read synchronously and remains owned by the caller. */
bool rdp_peer_send_progressive_frame(freerdp_peer *peer,
                                      IOSurfaceRef surface,
                                      uint32_t width, uint32_t height,
                                      const RECTANGLE_16 *dirtyRects,
                                      uint32_t dirtyRectCount,
                                      uint32_t *changedTilesOut);

bool rdp_peer_send_bitmap(freerdp_peer *peer,
                           const uint8_t *bgra, uint32_t x, uint32_t y,
                           uint32_t width, uint32_t height);

bool rdp_peer_send_audio(freerdp_peer *peer,
                          const int16_t *samples, uint32_t frame_count);

/* Negotiated client audio playback sample rate in Hz, or 0 if audio is not yet
 * activated (rdpsnd Activated callback has not fired, or no compatible format).
 *
 * rdpsnd does NOT resample: the client plays the PCM bytes we send at the rate
 * of the format IT selected. AudioCapture polls this to drive its resampler so
 * the captured/sent rate equals the client's playback rate (otherwise the audio
 * is pitch-shifted). Safe to call from any thread. */
uint32_t rdp_peer_get_audio_rate(freerdp_peer *peer);

bool rdp_peer_send_clipboard(freerdp_peer *peer,
                              const uint8_t *data, size_t len,
                              uint32_t format);

/* Advertise regular local files through MS-RDPECLIP FileGroupDescriptorW and
 * serve their bytes lazily when the RDP client pastes them. Directories,
 * symbolic links, files over 4 GiB and more than 256 files are rejected by the
 * initial bounded implementation. */
bool rdp_peer_send_clipboard_files(freerdp_peer *peer,
                                   const char *const *paths,
                                   size_t count);

/* Tell the client to render the default system pointer CLIENT-SIDE, so the cursor
 * tracks the local mouse smoothly instead of being tied to the (30fps) video. */
void rdp_peer_send_default_cursor(freerdp_peer *peer);

/* Keep the client-rendered pointer at the same RDP desktop coordinates as the
 * input event. Mobile clients can send absolute touch/mouse coordinates without
 * moving their own local pointer; the Position Update makes the cursor visible
 * and authoritative on those clients. */
void rdp_peer_send_cursor_position(freerdp_peer *peer,
                                   uint16_t x, uint16_t y);

/*
 * RDPDR (drive redirection) channel support.
 *
 * rdp_peer_open_rdpdr  — open the "rdpdr" WTS static virtual channel and send
 *   SERVER_ANNOUNCE. Should be called from peer_post_connect (or later once the
 *   VCM is ready). Returns true on success.
 *
 * rdp_peer_pump_rdpdr  — drain inbound rdpdr data and advance the MS-RDPEFS
 *   state machine. Call from the peer run loop whenever the rdpdr channel event
 *   is signaled, under xportLock.
 *
 * Both are no-ops when RDP_RDPDR_ENABLED != "1".
 */
bool rdp_peer_open_rdpdr(freerdp_peer *peer);
void rdp_peer_pump_rdpdr(freerdp_peer *peer);

/*
 * IRP send helpers — each sends one MS-RDPEFS IRP to the Windows client and
 * registers an optional async callback that fires (on the peer run-loop thread)
 * when the matching IOCOMPLETION arrives.  cb may be NULL for fire-and-forget.
 * All helpers MUST be called under xportLock.
 */

/* IRP_MJ_CREATE — open a file or directory on the client drive.
 * desiredAccess: GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000
 * createDisposition: FILE_OPEN=1, FILE_CREATE=2, FILE_OPEN_IF=3, FILE_OVERWRITE_IF=5
 * createOptions: FILE_DIRECTORY_FILE=0x1, FILE_NON_DIRECTORY_FILE=0x40 */
bool rdpdr_send_create_req(RDPPeerContext *ctx, uint32_t deviceId,
                           const char *path,
                           uint32_t desiredAccess,
                           uint32_t createDisposition,
                           uint32_t createOptions,
                           RDPIrpCallback cb, void *userdata);

/* IRP_MJ_CLOSE — close a file handle returned by CREATE. */
bool rdpdr_send_close_req(RDPPeerContext *ctx, uint32_t deviceId,
                          uint32_t fileId,
                          RDPIrpCallback cb, void *userdata);

/* IRP_MJ_READ — read bytes from an open file. */
bool rdpdr_send_read_req(RDPPeerContext *ctx, uint32_t deviceId,
                         uint32_t fileId, uint64_t offset, uint32_t length,
                         RDPIrpCallback cb, void *userdata);

/* IRP_MJ_WRITE — write bytes to an open file. */
bool rdpdr_send_write_req(RDPPeerContext *ctx, uint32_t deviceId,
                          uint32_t fileId, uint64_t offset,
                          const uint8_t *data, uint32_t length,
                          RDPIrpCallback cb, void *userdata);

/* IRP_MJ_DIRECTORY_CONTROL / IRP_MN_QUERY_DIRECTORY — list a directory.
 * informationClass: FileFullDirectoryInformation=2 */
bool rdpdr_send_query_dir_req(RDPPeerContext *ctx, uint32_t deviceId,
                              uint32_t fileId, const char *pattern,
                              RDPIrpCallback cb, void *userdata);

/* IRP_MJ_SET_INFORMATION (FileDispositionInformation) — mark file for deletion. */
bool rdpdr_send_delete_req(RDPPeerContext *ctx, uint32_t deviceId,
                           uint32_t fileId,
                           RDPIrpCallback cb, void *userdata);

/* Create Desktop placeholder folders for each redirected client drive and
 * register an NSFileProviderDomain (macOS 12+) for the drive.
 * Implemented in protocol/RDPDriveMount.m (ObjC/Foundation).
 * deviceId — the RDPDR device id from DEVICE_LIST_ANNOUNCE. */
void rdp_drive_mount_placeholder(const char *driveName, uint32_t deviceId);

/* Send the ACTUAL current cursor shape as an RDP color-pointer PDU so mstsc
 * renders the correct shape (I-beam, resize, hand, ...) client-side, lag-free.
 *
 * `bgra` is a 32-bit BGRA premultiplied, TOP-LEFT-origin, tightly packed
 * (stride == w*4) bitmap; w/h are in pixels (capped ~96; >96 uses the Large
 * pointer PDU). hotX/hotY are the hotspot in bitmap pixels. Internally builds a
 * bottom-up xor mask + a 1bpp AND mask from the alpha channel.
 *
 * Holds xportLock (transport write). No-op if the peer is not yet activated or
 * output is suppressed. Safe to call repeatedly; the caller should de-dupe
 * (only call when the shape actually changes). */
void rdp_peer_send_cursor_shape(freerdp_peer *peer,
                                const uint8_t *bgra, uint32_t w, uint32_t h,
                                uint16_t hotX, uint16_t hotY);
