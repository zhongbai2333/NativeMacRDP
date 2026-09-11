#define RDP_LOG_COMPONENT "peer"
#include "logging/RDPLog.h"

#define RDP_UDP_STATS_FRESH_MS             5000u
#define RDP_UDP_CONGESTION_RECENT_MS       3000u
#define RDP_UDP_FPS_PROMOTE_SAMPLES          30u
#define RDP_UDP_FPS_DEMOTE_SAMPLES            3u
#define RDP_TCP_FPS_PROMOTE_ACKS              90u
#define RDP_TCP_FPS_DEMOTE_ACKS                6u
#define RDP_TCP_FPS_MAX_BASE_RTT_MS           20u
#define RDP_TCP_FPS_PROMOTE_MIN_BYTES_PER_SEC 5000000u
#define RDP_TCP_FPS_DEMOTE_MAX_BYTES_PER_SEC  3000000u

#include "protocol/RDPPeer.h"
#include "protocol/RDPClientLiveness.h"
#include "protocol/RDPWebDAV.h"
#include "audio/AudioInput.h"

#include <freerdp/freerdp.h>
#include <freerdp/error.h>
#include <freerdp/autodetect.h>
#include <freerdp/listener.h>
#include <freerdp/server/rdpgfx.h>
#include <freerdp/server/disp.h>
#include <freerdp/server/cliprdr.h>
#include <freerdp/server/rdpsnd.h>
#include <freerdp/server/server-common.h>
#include <freerdp/channels/rdpgfx.h>
#include <freerdp/channels/wtsvc.h>
#include <freerdp/channels/drdynvc.h>
#include <freerdp/crypto/certificate.h>
#include <freerdp/crypto/privatekey.h>
#include <freerdp/session.h>
#include <freerdp/codec/progressive.h>
#include <freerdp/codec/color.h>
#include <freerdp/codec/region.h>
#include <freerdp/utils/cliprdr_utils.h>
#include <winpr/ssl.h>
#include <winpr/file.h>
#include <winpr/string.h>
#include <winpr/synch.h>
#include <winpr/sysinfo.h>
#include <winpr/wtsapi.h>
#include <winpr/stream.h>
#include <winpr/custom-crypto.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <IOSurface/IOSurface.h>

static void peer_apply_frame_rate(RDPPeerContext *ctx, uint32_t frameRate,
                                  const char *reason);

#ifndef RDPGFX_CAPS_FLAG_AVC_DISABLED
#define RDPGFX_CAPS_FLAG_AVC_DISABLED 0x00000020U
#endif
#ifndef RDPGFX_CAPS_FLAG_AVC420_ENABLED
#define RDPGFX_CAPS_FLAG_AVC420_ENABLED 0x00000010U
#endif

#define RDP_AUTODETECT_BANDWIDTH_SEQUENCE 0u
#define RDP_AUTODETECT_RESULT_SEQUENCE    0u
#define RDP_AUTODETECT_RTT_FIRST_SEQUENCE 1u
/* Match GNOME Remote Desktop's connect-time bandwidth sizing. A phase sends
 * 1, 4, or 16 of these payloads, using Payload PDUs for all but the last one
 * and carrying the last payload in the Stop PDU. */
#define RDP_AUTODETECT_PAYLOAD_BYTES      16320u
#define RDP_AUTODETECT_BW_MAX_RESPONSE_MS 400u
#define RDP_AUTODETECT_BW_MAX_DELTA_MS    100u
/* Windows App can advance to the MCS message-channel phase before a long
 * tail of connect-time RTT probes has completed. Keep enough samples to
 * reject a one-off spike, but finish well before that transition. Runtime
 * GFX ACK/QoE feedback continues adapting the pacing after activation. */
#define RDP_AUTODETECT_RTT_SAMPLES        5u
#define RDP_BACKGROUND_RESUME_PROBE_MS    1500u
#define RDP_BACKGROUND_SURFACE_PAUSE_MS   750u
#define RDP_BACKGROUND_SURFACE_SILENCE_MS 1500u

/* Registered clipboard format IDs are scoped to the endpoint and mapped by
 * their names. Keep ours stable within a session; the client keys file-copy on
 * "FileGroupDescriptorW", not on this numeric value. */
#define RDP_CLIPBOARD_FORMAT_PNG                         0xC004u
#define RDP_CLIPBOARD_FORMAT_FILE_GROUP_DESCRIPTOR_W     0xC005u
#define RDP_CLIPBOARD_FILE_MAX_COUNT                        256u
#define RDP_CLIPBOARD_FILE_MAX_CHUNK                    (64u * 1024u)
#define RDP_CLIPBOARD_INCOMING_MAX_FILE              (2ull * 1024ull * 1024ull * 1024ull)
#define RDP_CLIPBOARD_INCOMING_MAX_TOTAL             (4ull * 1024ull * 1024ull * 1024ull)

static void clipboard_file_set_free(char **paths, uint64_t *sizes,
                                    uint32_t count) {
    if (paths) {
        for (uint32_t i = 0; i < count; i++)
            free(paths[i]);
    }
    free(paths);
    free(sizes);
}

static void clipboard_incoming_reset(RDPPeerContext *ctx, bool removeFiles) {
    if (!ctx) return;
    if (ctx->clipIncomingFD >= 0) {
        close(ctx->clipIncomingFD);
        ctx->clipIncomingFD = -1;
    }
    if (removeFiles && ctx->clipIncomingPaths) {
        for (uint32_t i = 0; i < ctx->clipIncomingCount; i++) {
            if (ctx->clipIncomingPaths[i])
                unlink(ctx->clipIncomingPaths[i]);
        }
    }
    if (removeFiles && ctx->clipIncomingStagingDir)
        rmdir(ctx->clipIncomingStagingDir);
    clipboard_file_set_free(ctx->clipIncomingPaths,
                            ctx->clipIncomingSizes,
                            ctx->clipIncomingCount);
    free(ctx->clipIncomingStagingDir);
    ctx->clipIncomingStagingDir = NULL;
    ctx->clipIncomingPaths = NULL;
    ctx->clipIncomingSizes = NULL;
    ctx->clipIncomingCount = 0;
    ctx->clipIncomingIndex = 0;
    ctx->clipIncomingOffset = 0;
    ctx->clipIncomingExpectedStreamId = 0;
    ctx->clipIncomingRequestedBytes = 0;
    ctx->clipIncomingActive = false;
    ctx->clipIncomingPublished = false;
}

static bool clipboard_safe_flat_filename(const char *name) {
    if (!name || !*name || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return false;
    const size_t len = strlen(name);
    if (len == 0 || len > NAME_MAX) return false;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (*p == '/' || *p == '\\' || *p < 0x20 || *p == 0x7f)
            return false;
    }
    return true;
}

static bool clipboard_incoming_request_next(RDPPeerContext *ctx);

static bool clipboard_incoming_begin(RDPPeerContext *ctx,
                                     const BYTE *data, UINT32 len) {
    if (!ctx || !ctx->cliprdr || !ctx->callbacks.onClipboardFiles ||
        !data || len == 0)
        return false;

    FILEDESCRIPTORW *descriptors = NULL;
    UINT32 count = 0;
    UINT parseRc = cliprdr_parse_file_list(data, len, &descriptors, &count);
    if (parseRc != CHANNEL_RC_OK || !descriptors || count == 0 ||
        count > RDP_CLIPBOARD_FILE_MAX_COUNT) {
        rdp_info("clipboard: rejected client file list (parse=%u count=%u)",
                 parseRc, count);
        free(descriptors);
        return false;
    }

    clipboard_incoming_reset(ctx, true);
    ctx->clipIncomingCount = count;
    ctx->clipIncomingPaths = calloc(count, sizeof(*ctx->clipIncomingPaths));
    ctx->clipIncomingSizes = calloc(count, sizeof(*ctx->clipIncomingSizes));
    if (!ctx->clipIncomingPaths || !ctx->clipIncomingSizes)
        goto fail;

    char stagingTemplate[] = "/private/tmp/NativeMacRDP-clipboard-XXXXXX";
    char *created = mkdtemp(stagingTemplate);
    if (!created) {
        rdp_info("clipboard: could not create incoming staging directory: %s",
                 strerror(errno));
        goto fail;
    }
    ctx->clipIncomingStagingDir = strdup(created);
    if (!ctx->clipIncomingStagingDir) {
        rmdir(created);
        goto fail;
    }

    uint64_t totalSize = 0;
    for (UINT32 i = 0; i < count; i++) {
        const FILEDESCRIPTORW *descriptor = &descriptors[i];
        if ((descriptor->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            !(descriptor->dwFlags & FD_FILESIZE)) {
            rdp_info("clipboard: client file list contains a directory or "
                     "an entry without FD_FILESIZE");
            goto fail;
        }

        uint64_t size = ((uint64_t)descriptor->nFileSizeHigh << 32) |
                        (uint64_t)descriptor->nFileSizeLow;
        if (size > RDP_CLIPBOARD_INCOMING_MAX_FILE ||
            totalSize > RDP_CLIPBOARD_INCOMING_MAX_TOTAL - size) {
            rdp_info("clipboard: client file list exceeds the incoming size limit");
            goto fail;
        }
        totalSize += size;

        size_t wideLen = 0;
        while (wideLen < ARRAYSIZE(descriptor->cFileName) &&
               descriptor->cFileName[wideLen] != 0)
            wideLen++;
        if (wideLen == 0 || wideLen == ARRAYSIZE(descriptor->cFileName)) {
            rdp_info("clipboard: client supplied an unterminated or empty file name");
            goto fail;
        }
        char *name = ConvertWCharNToUtf8Alloc(descriptor->cFileName,
                                              wideLen, NULL);
        if (!name || !clipboard_safe_flat_filename(name)) {
            rdp_info("clipboard: client supplied an unsafe file name");
            free(name);
            goto fail;
        }

        const size_t pathLen = strlen(ctx->clipIncomingStagingDir) + 1 +
                               strlen(name) + 1;
        if (pathLen > PATH_MAX) {
            free(name);
            goto fail;
        }
        ctx->clipIncomingPaths[i] = malloc(pathLen);
        if (!ctx->clipIncomingPaths[i]) {
            free(name);
            goto fail;
        }
        snprintf(ctx->clipIncomingPaths[i], pathLen, "%s/%s",
                 ctx->clipIncomingStagingDir, name);
        free(name);
        ctx->clipIncomingSizes[i] = size;
    }
    free(descriptors);
    ctx->clipIncomingActive = true;
    ctx->clipIncomingPublished = false;
    ctx->clipIncomingIndex = 0;
    ctx->clipIncomingOffset = 0;
    rdp_info("clipboard: downloading %u Windows file(s), total=%llu bytes",
             count, (unsigned long long)totalSize);
    return clipboard_incoming_request_next(ctx);

fail:
    free(descriptors);
    clipboard_incoming_reset(ctx, true);
    return false;
}

static bool clipboard_incoming_publish(RDPPeerContext *ctx) {
    if (!ctx || !ctx->clipIncomingActive ||
        ctx->clipIncomingIndex != ctx->clipIncomingCount)
        return false;
    ctx->clipIncomingActive = false;
    ctx->clipIncomingPublished = true;
    const bool published = ctx->callbacks.onClipboardFiles(
        ctx->callbacks.userdata,
        (const char *const *)ctx->clipIncomingPaths,
        ctx->clipIncomingCount);
    if (!published) {
        rdp_info("clipboard: macOS rejected the downloaded file pasteboard");
        clipboard_incoming_reset(ctx, true);
        return false;
    }
    rdp_info("clipboard: Windows file download complete (%u file(s))",
             ctx->clipIncomingCount);
    return true;
}

static bool clipboard_incoming_request_next(RDPPeerContext *ctx) {
    if (!ctx || !ctx->clipIncomingActive) return false;

    while (ctx->clipIncomingIndex < ctx->clipIncomingCount) {
        const uint32_t index = ctx->clipIncomingIndex;
        const uint64_t size = ctx->clipIncomingSizes[index];
        if (ctx->clipIncomingFD < 0) {
            ctx->clipIncomingFD = open(ctx->clipIncomingPaths[index],
                                       O_WRONLY | O_CREAT | O_EXCL |
                                       O_CLOEXEC | O_NOFOLLOW, 0600);
            if (ctx->clipIncomingFD < 0) {
                rdp_info("clipboard: could not create staged file %u: %s",
                         index, strerror(errno));
                clipboard_incoming_reset(ctx, true);
                return false;
            }
        }
        if (ctx->clipIncomingOffset == size) {
            close(ctx->clipIncomingFD);
            ctx->clipIncomingFD = -1;
            ctx->clipIncomingIndex++;
            ctx->clipIncomingOffset = 0;
            continue;
        }

        const uint64_t remaining = size - ctx->clipIncomingOffset;
        const uint32_t requested = remaining > RDP_CLIPBOARD_FILE_MAX_CHUNK
            ? RDP_CLIPBOARD_FILE_MAX_CHUNK : (uint32_t)remaining;
        uint32_t streamId = ++ctx->clipIncomingNextStreamId;
        if (streamId == 0) streamId = ++ctx->clipIncomingNextStreamId;
        CLIPRDR_FILE_CONTENTS_REQUEST req = {0};
        req.common.msgType = CB_FILECONTENTS_REQUEST;
        req.streamId = streamId;
        req.listIndex = index;
        req.dwFlags = FILECONTENTS_RANGE;
        req.nPositionLow = (UINT32)ctx->clipIncomingOffset;
        req.nPositionHigh = (UINT32)(ctx->clipIncomingOffset >> 32);
        req.cbRequested = requested;
        ctx->clipIncomingExpectedStreamId = streamId;
        ctx->clipIncomingRequestedBytes = requested;
        UINT rc = ctx->cliprdr->ServerFileContentsRequest(ctx->cliprdr, &req);
        if (rc != CHANNEL_RC_OK) {
            rdp_info("clipboard: file range request failed (rc=%u)", rc);
            clipboard_incoming_reset(ctx, true);
            return false;
        }
        return true;
    }

    return clipboard_incoming_publish(ctx);
}

enum {
    RDP_NETWORK_DETECT_INITIAL = 0,
    RDP_NETWORK_DETECT_WAIT_BANDWIDTH_1,
    RDP_NETWORK_DETECT_WAIT_BANDWIDTH_2,
    RDP_NETWORK_DETECT_WAIT_BANDWIDTH_3,
    RDP_NETWORK_DETECT_WAIT_RTT,
    RDP_NETWORK_DETECT_COMPLETE,
};

/* ── MS-RDPEFS (rdpdr) protocol constants ──────────────────────────────── */
/* Packet ids from MS-RDPEFS specification §2.2.1.1 */
#define RDPDR_CTYP_CORE                  0x4472
#define PAKID_CORE_SERVER_ANNOUNCE       0x496E
#define PAKID_CORE_CLIENTID_CONFIRM      0x4343
#define PAKID_CORE_CLIENT_NAME           0x434E
#define PAKID_CORE_CAPABILITY_REQUEST    0x5350
#define PAKID_CORE_CAPABILITY_RESPONSE   0x4350
#define PAKID_CORE_CLIENT_ANNOUNCE_REPLY 0x4352
#define PAKID_CORE_DEVICE_LIST_ANNOUNCE  0x4441
#define PAKID_CORE_DEVICE_REPLY          0x6472
#define PAKID_CORE_DEVICE_IOCOMPLETION   0x4943   /* IRP I/O completion from client */
#define RDPDR_DTYP_FILESYSTEM            0x00000008
#define RDPDR_DTYP_PRINT                 0x00000004
#define RDPDR_DTYP_SERIAL                0x00000001
#define RDPDR_DTYP_PARALLEL              0x00000002
#define RDPDR_DTYP_SMARTCARD             0x00000020
#define CAP_GENERAL_TYPE                 0x0001
#define RDPDR_VERSION_MAJOR              0x0001
#define RDPDR_VERSION_MINOR              0x000C

/* IRP major function codes (MS-RDPEFS §2.2.1.4) — guard against WinPR
 * redefinition (winpr/ntdef.h or similar may define these). */
#ifndef IRP_MJ_CREATE
#define IRP_MJ_CREATE                    0x00000000
#endif
#ifndef IRP_MJ_CLOSE
#define IRP_MJ_CLOSE                     0x00000002
#endif
#ifndef IRP_MJ_READ
#define IRP_MJ_READ                      0x00000003
#endif
#ifndef IRP_MJ_WRITE
#define IRP_MJ_WRITE                     0x00000004
#endif
#ifndef IRP_MJ_QUERY_INFORMATION
#define IRP_MJ_QUERY_INFORMATION         0x00000005
#endif
#ifndef IRP_MJ_SET_INFORMATION
#define IRP_MJ_SET_INFORMATION           0x00000006
#endif
#ifndef IRP_MJ_DIRECTORY_CONTROL
#define IRP_MJ_DIRECTORY_CONTROL         0x0000000C
#endif

/* IRP minor functions for IRP_MJ_DIRECTORY_CONTROL */
#define IRP_MN_QUERY_DIRECTORY           0x00000001

/* PAKID_CORE_DEVICE_IOREQUEST — client-to-server IRP request packet */
#define PAKID_CORE_DEVICE_IOREQUEST      0x4952

/* IRP_MJ_QUERY_INFORMATION / IRP_MJ_SET_INFORMATION classes */
#define RDPDR_FileBasicInformation       0x00000004  /* timestamps + attrs */
#define RDPDR_FileStandardInformation    0x00000005  /* size + allocation */
#define RDPDR_FileDispositionInformation 0x0000000D  /* mark for deletion */
#define RDPDR_FileFullDirectoryInformation 0x00000002 /* directory listing */

/* NTSTATUS codes relevant to RDPDR — prefixed to avoid redefinition if WinPR
 * defines the generic STATUS_SUCCESS in its ntstatus.h. */
#define RDPDR_STATUS_SUCCESS             0x00000000
#define RDPDR_STATUS_NO_MORE_FILES       0x80000006  /* end of directory listing */

/* IRP_MJ_CREATE access and disposition constants */
#define RDPDR_GENERIC_READ               0x80000000
#define RDPDR_GENERIC_WRITE              0x40000000
#define RDPDR_FILE_OPEN                  0x00000001
#define RDPDR_FILE_CREATE                0x00000002
#define RDPDR_FILE_OPEN_IF               0x00000003
#define RDPDR_FILE_OVERWRITE_IF          0x00000005
#define RDPDR_FILE_DIRECTORY_FILE        0x00000001
#define RDPDR_FILE_NON_DIRECTORY_FILE    0x00000040
#define RDPDR_DELETE_ON_CLOSE            0x00001000

/* Handshake state for the rdpdr channel */
typedef enum {
    kRdpdrIdle = 0,
    kRdpdrSentAnnounce,
    kRdpdrReceivedName,
    kRdpdrReady,
    kRdpdrError,
} RdpdrHandshakeState;

/* TLS material directory. Defaults to /etc/macos-rdp (root LaunchDaemon model);
 * override with RDP_CERT_DIR when running as a LaunchAgent in the user session,
 * where the cert/key live somewhere the user can read. */
#ifndef RDP_CERT_DIR_DEFAULT
#define RDP_CERT_DIR_DEFAULT "/etc/macos-rdp"
#endif

/* ── Settings ──────────────────────────────────────────────────────────── */

static BOOL peer_network_detect_rtt_response(rdpAutoDetect *autoDetect,
                                             RDP_TRANSPORT_TYPE transport,
                                             UINT16 sequenceNumber) {
    (void)transport;
    RDPPeerContext *ctx = (RDPPeerContext *)autoDetect->custom;
    if (ctx && ctx->networkDetectPhase == RDP_NETWORK_DETECT_WAIT_RTT) {
        ctx->networkDetectRTTCount++;
        ctx->networkDetectRTTSumMS += autoDetect->netCharAverageRTT;
    }
    rdp_info("RDP network RTT response: sequence=%u sample=%u/%u rtt=%u ms "
             "base=%u ms",
             sequenceNumber, ctx ? ctx->networkDetectRTTCount : 0,
             RDP_AUTODETECT_RTT_SAMPLES, autoDetect->netCharAverageRTT,
             autoDetect->netCharBaseRTT);
    return TRUE;
}

static BOOL peer_network_detect_bandwidth_result(rdpAutoDetect *autoDetect,
                                                  RDP_TRANSPORT_TYPE transport,
                                                  UINT16 sequenceNumber,
                                                  UINT16 responseType,
                                                  UINT32 timeDelta,
                                                  UINT32 byteCount) {
    (void)transport;
    (void)responseType;
    RDPPeerContext *ctx = (RDPPeerContext *)autoDetect->custom;
    if (ctx) {
        const uint64_t now = GetTickCount64();
        const uint64_t elapsed = now >= ctx->networkDetectBandwidthStartMS
            ? now - ctx->networkDetectBandwidthStartMS : 0;
        ctx->networkDetectResponseLatencyMS =
            elapsed > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed;
        ctx->networkDetectTimeDeltaMS = timeDelta;
        ctx->networkDetectByteCount = byteCount;
    }

    /* timeDelta is milliseconds and the protocol field is decimal kbit/s, so
     * bytes * 8 / milliseconds has exactly the required unit. */
    UINT64 bandwidth = timeDelta ? ((UINT64)byteCount * 8u) / timeDelta : 0;
    if (bandwidth > UINT32_MAX)
        bandwidth = UINT32_MAX;
    autoDetect->netCharBandwidth = (UINT32)bandwidth;
    rdp_info("RDP network bandwidth response: sequence=%u bytes=%u time=%u ms "
             "response=%u ms bandwidth=%u kbit/s",
             sequenceNumber, byteCount, timeDelta,
             ctx ? ctx->networkDetectResponseLatencyMS : 0,
             autoDetect->netCharBandwidth);
    return TRUE;
}

static BOOL peer_network_detect_sync(rdpAutoDetect *autoDetect,
                                     RDP_TRANSPORT_TYPE transport,
                                     UINT16 sequenceNumber,
                                     UINT32 bandwidth, UINT32 rtt) {
    (void)transport;
    autoDetect->netCharBandwidth = bandwidth;
    autoDetect->netCharAverageRTT = rtt;
    rdp_info("RDP network characteristics sync: sequence=%u bandwidth=%u "
             "kbit/s rtt=%u ms",
             sequenceNumber, bandwidth, rtt);
    return TRUE;
}

static BOOL peer_network_detect_send_bandwidth(rdpAutoDetect *autoDetect,
                                                uint32_t payloadCount,
                                                uint8_t waitPhase) {
    RDPPeerContext *ctx = (RDPPeerContext *)autoDetect->custom;
    if (!ctx || payloadCount == 0 || !autoDetect->BandwidthMeasureStart ||
        !autoDetect->BandwidthMeasurePayload ||
        !autoDetect->BandwidthMeasureStop)
        return FALSE;

    ctx->networkDetectPhase = waitPhase;
    ctx->networkDetectBandwidthStartMS = GetTickCount64();
    if (!autoDetect->BandwidthMeasureStart(
            autoDetect, RDP_TRANSPORT_TCP,
            RDP_AUTODETECT_BANDWIDTH_SEQUENCE))
        return FALSE;
    for (uint32_t i = 1; i < payloadCount; i++) {
        if (!autoDetect->BandwidthMeasurePayload(
                autoDetect, RDP_TRANSPORT_TCP,
                RDP_AUTODETECT_BANDWIDTH_SEQUENCE,
                RDP_AUTODETECT_PAYLOAD_BYTES))
            return FALSE;
    }
    if (!autoDetect->BandwidthMeasureStop(
            autoDetect, RDP_TRANSPORT_TCP,
            RDP_AUTODETECT_BANDWIDTH_SEQUENCE,
            RDP_AUTODETECT_PAYLOAD_BYTES))
        return FALSE;

    rdp_info("RDP connect-time network detection: bandwidth phase sent "
             "(%u x %u-byte payloads)", payloadCount,
             RDP_AUTODETECT_PAYLOAD_BYTES);
    return TRUE;
}

static BOOL peer_network_detect_send_rtt(rdpAutoDetect *autoDetect) {
    RDPPeerContext *ctx = (RDPPeerContext *)autoDetect->custom;
    if (!ctx || !autoDetect->RTTMeasureRequest ||
        ctx->networkDetectRTTCount >= RDP_AUTODETECT_RTT_SAMPLES)
        return FALSE;

    const UINT16 sequence = (UINT16)(RDP_AUTODETECT_RTT_FIRST_SEQUENCE +
                                     ctx->networkDetectRTTCount);
    if (!autoDetect->RTTMeasureRequest(autoDetect, RDP_TRANSPORT_TCP, sequence))
        return FALSE;
    ctx->networkDetectPhase = RDP_NETWORK_DETECT_WAIT_RTT;
    rdp_debug("RDP connect-time network detection: RTT request %u/%u sent",
              ctx->networkDetectRTTCount + 1u, RDP_AUTODETECT_RTT_SAMPLES);
    return TRUE;
}

static void peer_network_detect_apply_pacing(RDPPeerContext *ctx,
                                             uint32_t bandwidthKbit,
                                             uint32_t baseRTTMS) {
    if (!ctx || bandwidthKbit == 0)
        return;

    const uint32_t target = rdp_tcp_latency_apply_network(
        &ctx->tcpLatency, bandwidthKbit, baseRTTMS, GetTickCount64());
    ctx->progressiveMaxQoeInflight = ctx->tcpLatency.maxInflightFrames;
    atomic_store_explicit(&ctx->progressiveBaseRTTMS, baseRTTMS,
                          memory_order_release);
    atomic_store_explicit(&ctx->progressiveTargetBytesPerSec, target,
                          memory_order_release);
    rdp_info("Progressive pacing initialized from network detection: "
             "measured=%u kbit/s target=%.1f Mbit/s configured-ceiling=%.1f "
             "Mbit/s base-rtt=%u ms in-flight=%u",
             bandwidthKbit, (double)target * 8.0 / 1000000.0,
             (double)ctx->progressiveMaxBytesPerSec * 8.0 / 1000000.0,
             baseRTTMS, ctx->progressiveMaxQoeInflight);
}

static FREERDP_AUTODETECT_STATE
peer_network_detect_begin(rdpAutoDetect *autoDetect) {
    RDPPeerContext *ctx = (RDPPeerContext *)autoDetect->custom;
    if (!ctx)
        return FREERDP_AUTODETECT_STATE_FAIL;

    ctx->networkDetectRTTCount = 0;
    ctx->networkDetectRTTSumMS = 0;
    if (!peer_network_detect_send_bandwidth(
            autoDetect, 1u, RDP_NETWORK_DETECT_WAIT_BANDWIDTH_1))
        return FREERDP_AUTODETECT_STATE_FAIL;
    return FREERDP_AUTODETECT_STATE_REQUEST;
}

static FREERDP_AUTODETECT_STATE
peer_network_detect_progress(rdpAutoDetect *autoDetect) {
    RDPPeerContext *ctx = (RDPPeerContext *)autoDetect->custom;
    if (!ctx)
        return FREERDP_AUTODETECT_STATE_FAIL;

    if (ctx->networkDetectPhase == RDP_NETWORK_DETECT_WAIT_BANDWIDTH_1 ||
        ctx->networkDetectPhase == RDP_NETWORK_DETECT_WAIT_BANDWIDTH_2) {
        const BOOL growSample =
            ctx->networkDetectResponseLatencyMS <
                RDP_AUTODETECT_BW_MAX_RESPONSE_MS &&
            ctx->networkDetectTimeDeltaMS < RDP_AUTODETECT_BW_MAX_DELTA_MS;
        if (growSample) {
            const BOOL firstPhase = ctx->networkDetectPhase ==
                                    RDP_NETWORK_DETECT_WAIT_BANDWIDTH_1;
            if (!peer_network_detect_send_bandwidth(
                    autoDetect, firstPhase ? 4u : 16u,
                    firstPhase ? RDP_NETWORK_DETECT_WAIT_BANDWIDTH_2
                               : RDP_NETWORK_DETECT_WAIT_BANDWIDTH_3))
                return FREERDP_AUTODETECT_STATE_FAIL;
            return FREERDP_AUTODETECT_STATE_REQUEST;
        }
        rdp_info("RDP connect-time network detection: keeping current bandwidth "
                 "sample (response=%u ms delta=%u ms)",
                 ctx->networkDetectResponseLatencyMS,
                 ctx->networkDetectTimeDeltaMS);
        if (!peer_network_detect_send_rtt(autoDetect))
            return FREERDP_AUTODETECT_STATE_FAIL;
        return FREERDP_AUTODETECT_STATE_REQUEST;
    }

    if (ctx->networkDetectPhase == RDP_NETWORK_DETECT_WAIT_BANDWIDTH_3) {
        if (!peer_network_detect_send_rtt(autoDetect))
            return FREERDP_AUTODETECT_STATE_FAIL;
        return FREERDP_AUTODETECT_STATE_REQUEST;
    }

    if (ctx->networkDetectPhase == RDP_NETWORK_DETECT_WAIT_RTT) {
        if (ctx->networkDetectRTTCount < RDP_AUTODETECT_RTT_SAMPLES) {
            if (!peer_network_detect_send_rtt(autoDetect))
                return FREERDP_AUTODETECT_STATE_FAIL;
            return FREERDP_AUTODETECT_STATE_REQUEST;
        }
        if (!autoDetect->NetworkCharacteristicsResult)
            return FREERDP_AUTODETECT_STATE_FAIL;

        autoDetect->netCharAverageRTT = (UINT32)(
            ctx->networkDetectRTTSumMS / ctx->networkDetectRTTCount);

        const rdpNetworkCharacteristicsResult result = {
            .type = RDP_NETCHAR_RESULT_TYPE_BASE_RTT_BW_AVG_RTT,
            .baseRTT = autoDetect->netCharBaseRTT,
            .averageRTT = autoDetect->netCharAverageRTT,
            .bandwidth = autoDetect->netCharBandwidth,
        };
        if (!autoDetect->NetworkCharacteristicsResult(
                autoDetect, RDP_TRANSPORT_TCP,
                RDP_AUTODETECT_RESULT_SEQUENCE, &result))
            return FREERDP_AUTODETECT_STATE_FAIL;

        peer_network_detect_apply_pacing(ctx, result.bandwidth,
                                         result.baseRTT);
        ctx->networkDetectPhase = RDP_NETWORK_DETECT_COMPLETE;
        rdp_info("RDP connect-time network detection complete: base=%u ms "
                 "average=%u ms bandwidth=%u kbit/s; result sent to client",
                 result.baseRTT, result.averageRTT, result.bandwidth);
        return FREERDP_AUTODETECT_STATE_COMPLETE;
    }

    return ctx->networkDetectPhase == RDP_NETWORK_DETECT_COMPLETE
               ? FREERDP_AUTODETECT_STATE_COMPLETE
               : FREERDP_AUTODETECT_STATE_FAIL;
}

static void peer_configure_network_auto_detect(freerdp_peer *peer, BOOL enabled) {
    if (!enabled)
        return;

    rdpAutoDetect *autoDetect = autodetect_get(peer->context);
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!autoDetect || !ctx) {
        rdp_error("RDP network auto-detect context unavailable");
        return;
    }

    autoDetect->custom = ctx;
    autoDetect->RTTMeasureResponse = peer_network_detect_rtt_response;
    autoDetect->BandwidthMeasureResults = peer_network_detect_bandwidth_result;
    autoDetect->NetworkCharacteristicsSync = peer_network_detect_sync;
    autoDetect->OnConnectTimeAutoDetectBegin = peer_network_detect_begin;
    autoDetect->OnConnectTimeAutoDetectProgress = peer_network_detect_progress;
}

/* Load the server certificate + private key into the peer settings. Without
 * these, the TLS handshake cannot complete and the client aborts with a
 * connection/security error (mstsc 0x904). Returns false if either is missing. */
static bool peer_load_certificate(freerdp_peer *peer) {
    rdpSettings *s = peer->context->settings;

    const char *dir = getenv("RDP_CERT_DIR");
    if (!dir || !*dir) dir = RDP_CERT_DIR_DEFAULT;
    char keyPath[1024], certPath[1024];
    snprintf(keyPath,  sizeof(keyPath),  "%s/server.key", dir);
    snprintf(certPath, sizeof(certPath), "%s/server.crt", dir);

    rdpPrivateKey *key = freerdp_key_new_from_file(keyPath);
    if (!key) {
        rdp_error("could not load private key %s — run gen-tls-cert.sh", keyPath);
        return false;
    }
    if (!freerdp_settings_set_pointer_len(s, FreeRDP_RdpServerRsaKey, key, 1)) {
        rdp_error("failed to set server RSA key");
        return false;
    }

    rdpCertificate *cert = freerdp_certificate_new_from_file(certPath);
    if (!cert) {
        rdp_error("could not load certificate %s — run gen-tls-cert.sh", certPath);
        return false;
    }
    if (!freerdp_settings_set_pointer_len(s, FreeRDP_RdpServerCertificate, cert, 1)) {
        rdp_error("failed to set server certificate");
        return false;
    }

    rdp_verbose("loaded TLS certificate and key");
    return true;
}

static void peer_apply_settings(freerdp_peer *peer) {
    rdpSettings *s = peer->context->settings;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    const char *udpMultitransport = getenv("RDP_UDP_MULTITRANSPORT");
    const BOOL udpEnabled = ctx->callbacks.allowMultitransport &&
                            udpMultitransport &&
                            strcmp(udpMultitransport, "1") == 0;
    const char *networkAutoDetect = getenv("RDP_NETWORK_AUTO_DETECT");
    const BOOL networkAutoDetectEnabled =
        networkAutoDetect && strcmp(networkAutoDetect, "1") == 0;
    /* Only set what we actually use. Every extra setting is dead weight. */
    /* Network auto-detection is opt-in because it inserts the MS-RDPBCGR
     * connect-time RTT exchange before licensing. Keep the established
     * endpoint unchanged while allowing the isolated endpoint to exercise
     * the standard RTT/bandwidth measurement path used by connection-info
     * UIs and transport selection. */
    freerdp_settings_set_bool(s,   FreeRDP_NetworkAutoDetect,
                              networkAutoDetectEnabled);
    peer_configure_network_auto_detect(peer, networkAutoDetectEnabled);
    rdp_info("RDP network auto-detect: %s",
             networkAutoDetectEnabled ? "enabled" : "disabled");
    /* FreeRDP 3.30 has server-side MS-RDPEMT negotiation but no UDP socket or
     * RDPUDP2 data plane. Keep this strictly opt-in so the established TCP
     * endpoint cannot enter the bootstrap state accidentally. The isolated
     * UDP endpoint supplies the listener while the remaining transport layers
     * are implemented and verified. */
    freerdp_settings_set_bool(s,   FreeRDP_SupportMultitransport,   udpEnabled);
    freerdp_settings_set_uint32(s, FreeRDP_MultitransportFlags,
                                udpEnabled ? 0x00000201u : 0u); /* UDPFECR + Soft-Sync */
    freerdp_settings_set_bool(s,   FreeRDP_SupportGraphicsPipeline, TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_GfxH264,                 TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_GfxAVC444,               FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_GfxSmallCache,           FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_GfxThinClient,           FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_RemoteFxCodec,           FALSE);
    /* FreeRDP's own shadow server marks pointer updates as broken with bulk
     * compression + mstsc. Disable bulk compression, but keep Fast-Path Output
     * enabled: FreeRDP's server-side Pointer* callbacks are implemented by the
     * fast-path sender and otherwise reject every cursor PDU before it reaches
     * the client. RDPGFX Progressive is a DVC with its own codec. */
    freerdp_settings_set_bool(s,   FreeRDP_CompressionEnabled,      FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_FastPathOutput,          TRUE);
    /* Advertise both sides of the standard minimize/restore path explicitly.
     * Windows App may use Refresh Rect, rather than Suppress Output allow, when
     * its foreground renderer is recreated after iPadOS backgrounds the app. */
    freerdp_settings_set_bool(s,   FreeRDP_RefreshRect,             TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_SuppressOutput,          TRUE);
    /* FreeRDP 3.30's server defaults VCChunkSize to the protocol maximum
     * (16256), but its server-side ChannelPduTracker still owns a fixed
     * CHANNEL_PDU_LENGTH buffer and rejects any single SVC fragment larger
     * than CHANNEL_CHUNK_LENGTH (1600). mstsc follows the advertised maximum
     * when returning a large CLIPRDR file payload, which otherwise trips the
     * tracker assertion and aborts the entire daemon. Advertise the size the
     * tracker can actually consume until that FreeRDP mismatch is fixed. */
    freerdp_settings_set_uint32(s, FreeRDP_VCChunkSize,
                                CHANNEL_CHUNK_LENGTH);
    /* Explicitly advertise the same pointer capabilities we implement. Leaving
     * the server-side defaults implicit can produce a zero-sized cache in the
     * Demand Active PDU even when the client's Confirm Active advertises slots. */
    freerdp_settings_set_uint32(s, FreeRDP_ColorPointerCacheSize,   32);
    freerdp_settings_set_uint32(s, FreeRDP_PointerCacheSize,        32);
    freerdp_settings_set_uint32(s, FreeRDP_LargePointerFlag,        0x00000001);
    freerdp_settings_set_uint32(s, FreeRDP_MultifragMaxRequestSize, 0x00100000);
    /* Security: match the known-good sample-server config. Crucially disable
     * NLA — it requires NTLM/md4, which our minimal OpenSSL build omits (the
     * "md4 NTLM support not available" log line). Offer TLS (+ legacy RDP as a
     * fallback) so mstsc negotiates TLS. */
    freerdp_settings_set_bool(s,   FreeRDP_UseRdpSecurityLayer,     FALSE);
    freerdp_settings_set_bool(s,   FreeRDP_RdpSecurity,             TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_TlsSecurity,             TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_NlaSecurity,             FALSE);
    freerdp_settings_set_uint32(s, FreeRDP_TlsSecLevel,             1);
    freerdp_settings_set_uint32(s, FreeRDP_ColorDepth,              32);
    /* Unicode input is the useful default for mobile software keyboards: the
     * client-side IME commits UTF-16 text and we insert that text on the Mac.
     * Setting RDP_UNICODE_INPUT=0 removes INPUT_FLAG_UNICODE so the client sends
     * scan codes instead; that path feeds the active macOS input method and is
     * preferable when the user wants the Mac's own composition/candidate UI. */
    const char *unicodeInput = getenv("RDP_UNICODE_INPUT");
    const BOOL unicodeEnabled = !(unicodeInput && strcmp(unicodeInput, "0") == 0);
    freerdp_settings_set_bool(s,   FreeRDP_UnicodeInput,            unicodeEnabled);
    freerdp_settings_set_bool(s,   FreeRDP_HasHorizontalWheel,      TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_HasExtendedMouseEvent,   TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_SoundBeepsEnabled,       FALSE);
    /* Accept multi-monitor connections: client may send monitor layout data
     * (e.g. "Use all my monitors" in mstsc). We create one virtual display
     * sized to the combined DesktopWidth × DesktopHeight, which covers both
     * the span case and the independent-monitor case from the server's side. */
    freerdp_settings_set_bool(s,   FreeRDP_UseMultimon,             TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_SupportMonitorLayoutPdu, TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_DesktopResize,            TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_SupportDisplayControl,    TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_DynamicResolutionUpdate,  TRUE);
    freerdp_settings_set_bool(s,   FreeRDP_AutoReconnectionEnabled,  TRUE);

    peer_load_certificate(peer);
    rdp_info("keyboard text mode: %s (RDP_UNICODE_INPUT=%s)",
             unicodeEnabled ? "client IME / Unicode commit" : "macOS IME / scan codes",
             unicodeInput ? unicodeInput : "default:1");
    rdp_info("RDP UDP multitransport: %s",
             udpEnabled ? "advertised on isolated endpoint" : "disabled");
    rdp_info("static virtual-channel chunk size: %u bytes",
             (unsigned)freerdp_settings_get_uint32(s, FreeRDP_VCChunkSize));
    rdp_debug("peer settings applied");
}

#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
/* Exported by our private FreeRDP 3.30 build.  The upstream server creates the
 * request ID and cookie inside its private rdpMultitransport object; this hook
 * publishes them to the same-port UDP listener before the TCP request is sent. */
typedef BOOL (*RDPPrivateMultitransportBootstrap)(freerdp_peer *, UINT32,
                                                  const BYTE *, size_t, void *);
extern BOOL freerdp_peer_set_multitransport_bootstrap_handler(
    freerdp_peer *peer, RDPPrivateMultitransportBootstrap callback,
    void *userData);

static BOOL peer_multitransport_bootstrap(freerdp_peer *peer, UINT32 requestID,
                                          const BYTE *cookie,
                                          size_t cookieLength, void *userData) {
    (void)peer;
    RDPPeerContext *ctx = userData;
    if (!ctx || !cookie || cookieLength != 16 ||
        !ctx->callbacks.onMultitransportBootstrap)
        return FALSE;
    return ctx->callbacks.onMultitransportBootstrap(
               ctx->callbacks.userdata, requestID, cookie)
               ? TRUE
               : FALSE;
}

static BOOL peer_dvc_tunnel_send(void *userData, const BYTE *data, UINT32 length) {
    RDPPeerContext *ctx = userData;
    if (!ctx || !data || !length || !ctx->callbacks.onDVCTunnelSend)
        return FALSE;
    return ctx->callbacks.onDVCTunnelSend(ctx->callbacks.userdata, data, length)
               ? TRUE
               : FALSE;
}
#endif

/* ── Context lifecycle ─────────────────────────────────────────────────── */

static BOOL context_new(freerdp_peer *peer, rdpContext *ctx) {
    RDPPeerContext *c = (RDPPeerContext *)ctx;
    c->clipIncomingFD = -1;
    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&c->xportLock, &mattr);
    pthread_mutexattr_destroy(&mattr);
    region16_init(&c->progressivePendingRegion);
    c->progressivePendingRegionInitialized = true;

    /* End-to-end byte pacing remains active even when a client explicitly
     * suspends RDPGFX frame ACKs. That avoids filling TCP/FRP with tens of
     * megabits of disposable Progressive frames. The target is adaptive:
     * concrete client queue reports reduce it, sustained decoded ACKs recover
     * it slowly. Override the ceiling with RDP_PROGRESSIVE_MBIT. */
    double maxMbit = 20.0;
    const char *rateEnv = getenv("RDP_PROGRESSIVE_MBIT");
    if (rateEnv && *rateEnv) {
        char *end = NULL;
        double parsed = strtod(rateEnv, &end);
        if (end && *end == '\0' && parsed >= 1.0 && parsed <= 200.0)
            maxMbit = parsed;
        else
            rdp_error("invalid RDP_PROGRESSIVE_MBIT='%s'; using 20 Mbit/s", rateEnv);
    }
    c->progressiveMaxBytesPerSec = (uint32_t)(maxMbit * 125000.0);
    double minMbit = 2.0;
    const char *minRateEnv = getenv("RDP_PROGRESSIVE_MIN_MBIT");
    if (minRateEnv && *minRateEnv) {
        char *end = NULL;
        double parsed = strtod(minRateEnv, &end);
        if (end && *end == '\0' && parsed >= 0.5 && parsed <= maxMbit)
            minMbit = parsed;
        else
            rdp_error("invalid RDP_PROGRESSIVE_MIN_MBIT='%s'; using 2 Mbit/s",
                      minRateEnv);
    }
    if (minMbit > maxMbit)
        minMbit = maxMbit;
    c->progressiveMinBytesPerSec = (uint32_t)(minMbit * 125000.0);
    if (c->progressiveMinBytesPerSec > c->progressiveMaxBytesPerSec)
        c->progressiveMinBytesPerSec = c->progressiveMaxBytesPerSec;
    uint32_t explicitQoeInflight = 0u;
    const char *qoeInflightEnv = getenv("RDP_QOE_MAX_INFLIGHT");
    if (qoeInflightEnv && *qoeInflightEnv) {
        char *end = NULL;
        unsigned long parsed = strtoul(qoeInflightEnv, &end, 10);
        if (end && *end == '\0' && parsed >= 2u && parsed <= 60u)
            explicitQoeInflight = (uint32_t)parsed;
        else
            rdp_error("invalid RDP_QOE_MAX_INFLIGHT='%s'; using RTT-aware default",
                      qoeInflightEnv);
    }
    rdp_tcp_latency_init(&c->tcpLatency, c->progressiveMinBytesPerSec,
                         c->progressiveMaxBytesPerSec, explicitQoeInflight);
    c->progressiveMaxQoeInflight = c->tcpLatency.maxInflightFrames;
    c->clientLivenessTimeoutMS = 20000u;
    const char *livenessEnv = getenv("RDP_CLIENT_LIVENESS_TIMEOUT_SECONDS");
    if (livenessEnv && *livenessEnv) {
        char *end = NULL;
        unsigned long parsed = strtoul(livenessEnv, &end, 10);
        if (end && *end == '\0' && parsed >= 10u && parsed <= 120u)
            c->clientLivenessTimeoutMS = (uint32_t)parsed * 1000u;
        else
            rdp_error("invalid RDP_CLIENT_LIVENESS_TIMEOUT_SECONDS='%s'; "
                      "using 20 seconds", livenessEnv);
    }
    atomic_store_explicit(&c->progressiveTargetBytesPerSec,
                          c->tcpLatency.currentBytesPerSec,
                          memory_order_relaxed);
    rdp_info("Progressive TCP pacing: configured ceiling %.1f Mbit/s, floor "
             "%.1f Mbit/s, QoE backlog %s (%u frame(s) before RTT sample)",
             (double)c->progressiveMaxBytesPerSec * 8.0 / 1000000.0,
             (double)c->progressiveMinBytesPerSec * 8.0 / 1000000.0,
             explicitQoeInflight ? "fixed" : "RTT-aware",
             c->progressiveMaxQoeInflight);
    rdp_info("client graphics liveness timeout: %u seconds",
             c->clientLivenessTimeoutMS / 1000u);

    bool motionQualityEnabled = false;
    uint8_t motionQuantStep = 1u;
    uint32_t motionExitMS = 1200u;
    c->progressiveRefineMaxTiles = 96u;
#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
    motionQualityEnabled = true;
    const char *motionQualityEnv = getenv("RDP_PROGRESSIVE_MOTION_QUALITY");
    if (motionQualityEnv && *motionQualityEnv)
        motionQualityEnabled = strcmp(motionQualityEnv, "0") != 0 &&
                               strcasecmp(motionQualityEnv, "false") != 0 &&
                               strcasecmp(motionQualityEnv, "no") != 0;
    const char *motionStepEnv = getenv("RDP_PROGRESSIVE_MOTION_QUANT_STEP");
    if (motionStepEnv && *motionStepEnv) {
        char *end = NULL;
        unsigned long parsed = strtoul(motionStepEnv, &end, 10);
        if (end && *end == '\0' && parsed >= 1u && parsed <= 3u)
            motionQuantStep = (uint8_t)parsed;
        else
            rdp_error("invalid RDP_PROGRESSIVE_MOTION_QUANT_STEP='%s'; using 1",
                      motionStepEnv);
    }
    const char *motionExitEnv = getenv("RDP_PROGRESSIVE_MOTION_EXIT_MS");
    if (motionExitEnv && *motionExitEnv) {
        char *end = NULL;
        unsigned long parsed = strtoul(motionExitEnv, &end, 10);
        if (end && *end == '\0' && parsed >= 250u && parsed <= 3000u)
            motionExitMS = (uint32_t)parsed;
        else
            rdp_error("invalid RDP_PROGRESSIVE_MOTION_EXIT_MS='%s'; using 1200",
                      motionExitEnv);
    }
    const char *refineTilesEnv = getenv("RDP_PROGRESSIVE_REFINE_TILES");
    if (refineTilesEnv && *refineTilesEnv) {
        char *end = NULL;
        unsigned long parsed = strtoul(refineTilesEnv, &end, 10);
        if (end && *end == '\0' && parsed >= 8u && parsed <= 256u)
            c->progressiveRefineMaxTiles = (uint32_t)parsed;
        else
            rdp_error("invalid RDP_PROGRESSIVE_REFINE_TILES='%s'; using 96",
                      refineTilesEnv);
    }
#endif
    rdp_progressive_quality_init(&c->progressiveQuality,
                                 motionQualityEnabled,
                                 motionQuantStep, motionExitMS);
    rdp_info("Progressive motion quality: %s, base quant step=%u, "
             "entry=2 large frames (>=50%% immediate), restore=%u ms, "
             "refine<=%u tiles/frame",
             motionQualityEnabled ? "ON" : "OFF",
             motionQuantStep, motionExitMS, c->progressiveRefineMaxTiles);
    /* Open the Virtual Channel Manager — all dynamic channels live under it. */
    c->vcm = WTSOpenServerA((LPSTR)peer->context);
    if (!c->vcm || c->vcm == INVALID_HANDLE_VALUE) {
        rdp_error("WTSOpenServerA failed");
        return FALSE;
    }
#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
    WTSVirtualChannelManagerSetDVCTunnelCallback(c->vcm,
                                                 peer_dvc_tunnel_send, c);
#endif
    rdp_debug("VCM opened");
    return TRUE;
}

static void context_free(freerdp_peer *peer, rdpContext *ctx) {
    (void)peer;
    RDPPeerContext *c = (RDPPeerContext *)ctx;
    if (c->progressiveCodec) {
        progressive_context_free((PROGRESSIVE_CONTEXT *)c->progressiveCodec);
        c->progressiveCodec = NULL;
    }
    if (c->progressivePendingRegionInitialized) {
        region16_uninit(&c->progressivePendingRegion);
        c->progressivePendingRegionInitialized = false;
    }
    free(c->progressiveReferencePixels);
    c->progressiveReferencePixels = NULL;
    free(c->progressiveTileMask);
    c->progressiveTileMask = NULL;
    free(c->progressiveLowQualityTiles);
    c->progressiveLowQualityTiles = NULL;
    /* Unmount and destroy WebDAV servers first — they hold a pointer to the peer
     * which must still be valid when we call destroy. */
    for (int i = 0; i < RDPDR_MAX_DEVICES; i++) {
        if (c->webdavServers[i]) {
            rdp_webdav_unmount(c->webdavServers[i]);
            rdp_webdav_server_destroy(c->webdavServers[i]);
            c->webdavServers[i] = NULL;
        }
    }
    if (c->gfx)    { rdpgfx_server_context_free(c->gfx);    c->gfx    = NULL; }
    if (c->disp)   { disp_server_context_free(c->disp);      c->disp   = NULL; }
    if (c->cliprdr){ cliprdr_server_context_free(c->cliprdr);c->cliprdr= NULL; }
    if (c->rdpsnd) { rdpsnd_server_context_free(c->rdpsnd);  c->rdpsnd = NULL; }
    /* Audio input (MS-RDPEAI) — close and release the ObjC object. */
    if (c->audioInput) { rdp_audio_input_close(c->audioInput); c->audioInput = NULL; }
    /* Close rdpdr raw WTS channel (opened when RDP_RDPDR_ENABLED=1). */
    if (c->rdpdrChannel && c->rdpdrChannel != INVALID_HANDLE_VALUE) {
        WTSVirtualChannelClose(c->rdpdrChannel);
        c->rdpdrChannel = NULL;
        c->rdpdrEvent   = NULL;
    }
    if (c->vcm)    { WTSCloseServer(c->vcm);                 c->vcm    = NULL; }
    if (c->clipData) { free(c->clipData); c->clipData = NULL; c->clipLen = 0; }
    clipboard_file_set_free(c->clipFilePaths, c->clipFileSizes,
                            c->clipFileCount);
    c->clipFilePaths = NULL;
    c->clipFileSizes = NULL;
    c->clipFileCount = 0;
    /* Completed files may still be referenced by the global pasteboard after
     * the RDP session closes, so retain successful staging directories until
     * macOS clears /private/tmp. Incomplete transfers are deleted immediately. */
    clipboard_incoming_reset(c, !c->clipIncomingPublished);
    pthread_mutex_destroy(&c->xportLock);
    rdp_debug("peer context freed");
}

/* ── Input callbacks ───────────────────────────────────────────────────── */

static void peer_restore_output(RDPPeerContext *ctx, const char *reason,
                                bool clientEvidence) {
    if (!ctx) return;

    const uint64_t nowMS = GetTickCount64();
    const uint64_t sinceMS = ctx->outputSuppressedSinceMS;
    const uint64_t previousResponseMS = atomic_load_explicit(
        &ctx->lastClientResponseMS, memory_order_acquire);
    const uint64_t pausedMS = sinceMS && nowMS >= sinceMS
        ? nowMS - sinceMS : 0u;
    const uint64_t silenceMS = previousResponseMS && nowMS >= previousResponseMS
        ? nowMS - previousResponseMS : 0u;
    const bool recoveryEpisode = ctx->outputSuppressed ||
                                 ctx->outputResumeProbeAttempted ||
                                 sinceMS != 0u;
    ctx->outputSuppressed = false;

    /* Treat a foreground/input signal as fresh client activity. Otherwise a
     * long background interval would make the ordinary graphics watchdog fire
     * immediately after we submit the first recovery frame, before its ACK can
     * make the round trip. */
    if (clientEvidence) {
        if (recoveryEpisode && rdp_client_liveness_surface_resync_due(
                ctx->outputResumeProbeAttempted, pausedMS, silenceMS,
                RDP_BACKGROUND_SURFACE_PAUSE_MS,
                RDP_BACKGROUND_SURFACE_SILENCE_MS)) {
            atomic_store_explicit(&ctx->pendingGraphicsResync, true,
                                  memory_order_release);
            rdp_info("foreground recovery queued RDPGFX surface resync "
                     "(pause=%llums silence=%llums probe=%s)",
                     (unsigned long long)pausedMS,
                     (unsigned long long)silenceMS,
                     ctx->outputResumeProbeAttempted ? "yes" : "no");
        }
        atomic_store_explicit(&ctx->lastClientResponseMS, nowMS,
                              memory_order_release);
        ctx->outputResumeProbeAttempted = false;
        ctx->outputSuppressedSinceMS = 0u;
    } else {
        /* Preserve the original suppression timestamp until actual foreground
         * evidence arrives. The probe permits one repaint, but it must not make
         * a still-backgrounded client look fully restored. */
        ctx->outputResumeProbeAttempted = true;
    }

    /* AVC needs an IDR. Progressive keeps its codec stream, but invalidate the
     * pixel reference so the next capture callback sends every tile rather than
     * relying on damage metadata accumulated while output was paused. */
    ctx->sentKeyframe = false;
    ctx->keyframeRequested = false;
    if (ctx->graphicsMode == RDPGraphicsModeProgressive) {
        ctx->progressiveReferenceValid = false;
        if (ctx->progressivePendingRegionInitialized)
            region16_clear(&ctx->progressivePendingRegion);
        if (ctx->progressiveLowQualityTiles) {
            memset(ctx->progressiveLowQualityTiles, 0,
                   (size_t)ctx->progressiveTileColumns *
                   ctx->progressiveTileRows);
        }
        ctx->progressiveRefinementCursor = 0u;
    }
    if (ctx->callbacks.onKeyframeRequest) {
        ctx->keyframeRequested = true;
        ctx->callbacks.onKeyframeRequest(ctx->callbacks.userdata);
    }

    rdp_info("client output restored by %s after %llums; forcing full refresh",
             reason ? reason : "client activity",
             (unsigned long long)pausedMS);
}

static void peer_restore_output_on_activity(RDPPeerContext *ctx,
                                            const char *reason) {
    if (ctx && (ctx->outputSuppressed || ctx->outputResumeProbeAttempted))
        peer_restore_output(ctx, reason, true);
}

static BOOL peer_refresh_rect(rdpContext *context, BYTE count,
                              const RECTANGLE_16 *areas) {
    if (!context || (count > 0u && !areas)) return FALSE;
    RDPPeerContext *ctx = (RDPPeerContext *)context;
    rdp_info("client Refresh Rect received (%u area%s); forcing full refresh",
             count, count == 1u ? "" : "s");
    peer_restore_output(ctx, "Refresh Rect", true);
    return TRUE;
}

static BOOL peer_synchronize(rdpInput *input, UINT32 flags) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    peer_restore_output_on_activity(ctx, "input synchronize");
    if (ctx->callbacks.onKeyboardReset)
        ctx->callbacks.onKeyboardReset(ctx->callbacks.userdata);
    rdp_info("keyboard trace: synchronize flags=0x%08x", flags);
    return TRUE;
}

static BOOL peer_keyboard(rdpInput *input, UINT16 flags, UINT8 code) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    peer_restore_output_on_activity(ctx, "keyboard input");
    /* Temporary narrow trace for the reported D/E and Command problem. Avoid
     * logging arbitrary text/password scan codes. */
    if (code == 0x12 || code == 0x20 || code == 0x2E || code == 0x2F ||
        code == 0x1D || code == 0x2A || code == 0x36 || code == 0x38 ||
        code == 0x5B || code == 0x5C) {
        rdp_info("keyboard trace: scan flags=0x%04x code=0x%02x", flags, code);
    }
    if (ctx->callbacks.onKeyboard)
        ctx->callbacks.onKeyboard(ctx->callbacks.userdata, flags, code);
    return TRUE;
}

static BOOL peer_unicode_keyboard(rdpInput *input, UINT16 flags, UINT16 code) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    peer_restore_output_on_activity(ctx, "Unicode input");
    if (code == 'd' || code == 'D' || code == 'e' || code == 'E' ||
        code == 'c' || code == 'C' || code == 'v' || code == 'V') {
        rdp_info("keyboard trace: unicode flags=0x%04x code=U+%04X",
                 flags, code);
    }
    if (ctx->callbacks.onUnicodeKeyboard)
        ctx->callbacks.onUnicodeKeyboard(ctx->callbacks.userdata, flags, code);
    return TRUE;
}

static BOOL peer_mouse(rdpInput *input, UINT16 flags, UINT16 x, UINT16 y) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    peer_restore_output_on_activity(ctx, "pointer input");
    if (ctx->callbacks.onMouse)
        ctx->callbacks.onMouse(ctx->callbacks.userdata, flags, x, y);
    return TRUE;
}

static BOOL peer_mouse_ex(rdpInput *input, UINT16 flags, UINT16 x, UINT16 y) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    peer_restore_output_on_activity(ctx, "extended pointer input");
    if (ctx->callbacks.onMouseEx)
        ctx->callbacks.onMouseEx(ctx->callbacks.userdata, flags, x, y);
    return TRUE;
}

static BOOL peer_focus_in(rdpInput *input, UINT16 toggleStates) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    peer_restore_output_on_activity(ctx, "focus-in");
    if (ctx->callbacks.onKeyboardReset)
        ctx->callbacks.onKeyboardReset(ctx->callbacks.userdata);
    rdp_info("keyboard trace: focus-in toggles=0x%04x", toggleStates);
    return TRUE;
}

static BOOL peer_keyboard_pause(rdpInput *input) {
    (void)input;
    rdp_debug("input keyboard-pause");
    return TRUE;
}

static BOOL peer_rel_mouse(rdpInput *input, UINT16 flags, INT16 xDelta,
                           INT16 yDelta) {
    RDPPeerContext *ctx = (RDPPeerContext *)input->context;
    peer_restore_output_on_activity(ctx, "relative pointer input");
    rdp_debug("relative mouse ignored flags=0x%04x dx=%d dy=%d",
              flags, xDelta, yDelta);
    return TRUE;
}

static BOOL peer_qoe(rdpInput *input, UINT32 timestampMS) {
    (void)input;
    (void)timestampMS;
    return TRUE;
}

/* ── GFX caps negotiation ──────────────────────────────────────────────── */

static bool capset_supports_avc(const RDPGFX_CAPSET *caps) {
    if (!caps) return false;
    if (caps->version == RDPGFX_CAPVERSION_81)
        return (caps->flags & RDPGFX_CAPS_FLAG_AVC420_ENABLED) != 0;
    if (caps->version == RDPGFX_CAPVERSION_101)
        return true; /* AVC444v2 is implied by this capability version. */
    if (caps->version >= RDPGFX_CAPVERSION_10)
        return (caps->flags & RDPGFX_CAPS_FLAG_AVC_DISABLED) == 0;
    return false;
}

static const char *graphics_policy(void) {
    const char *policy = getenv("RDP_CODEC_POLICY");
    if (!policy || !*policy) return "auto";
    return policy;
}

/* Prefer a genuinely interactive refresh rate at iPad-sized resolutions, but
 * scale down before Progressive's CPU tile comparison becomes expensive. The
 * explicit override makes A/B testing possible without rebuilding. */
static uint32_t progressive_frame_rate(uint32_t width, uint32_t height) {
    const char *env = getenv("RDP_FRAME_RATE");
    if (env && *env) {
        char *end = NULL;
        unsigned long parsed = strtoul(env, &end, 10);
        if (end && *end == '\0' && parsed >= 8u && parsed <= 60u)
            return (uint32_t)parsed;
        rdp_error("invalid RDP_FRAME_RATE='%s'; using resolution-aware default", env);
    }

    const uint64_t pixels = (uint64_t)width * (uint64_t)height;
    if (pixels <= 4000000ULL) return 60u;
    if (pixels <= 8500000ULL) return 30u;
    return 15u;
}

static uint32_t progressive_max_frame_rate(uint32_t width, uint32_t height,
                                           uint32_t baseRate) {
    /* An explicit override is a hard ceiling. Without one, permit the common
     * 2560x1600 iPad canvas to promote from 30 to 60 only after a healthy
     * transport path has been observed. Larger desktops retain the CPU-safe
     * resolution-aware rate. */
    const char *env = getenv("RDP_FRAME_RATE");
    if (env && *env) return baseRate;
    const uint64_t pixels = (uint64_t)width * (uint64_t)height;
    return pixels <= 4500000ULL ? 60u : baseRate;
}

#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
static bool progressive_apply_quant_step(RDPPeerContext *ctx, uint8_t step) {
    static const UINT32 normalQuant[10] = {
        6u, 6u, 6u, 6u, 7u, 7u, 8u, 8u, 8u, 9u
    };
    /* Use three protocol quantization tables: Y may discard only high-frequency
     * detail during motion, while Cb/Cr and Y's LL/L3 bands stay untouched.
     * Applying one stronger table to all three components produced the visible
     * 64x64 magenta blocks in Windows App on weak links: every tile's average
     * chroma was being coarsened by as much as +3. */
    UINT32 quant[30] = {0};
    if (!ctx || !ctx->progressiveCodec || step > 3u)
        return false;
    for (size_t component = 0; component < 3u; component++) {
        for (size_t band = 0; band < 10u; band++) {
            uint32_t value = normalQuant[band];
            if (component == 0u && band >= 4u)
                value += step;
            quant[component * 10u + band] = value > 15u ? 15u : value;
        }
    }
    return progressive_context_set_quantization(
        (PROGRESSIVE_CONTEXT *)ctx->progressiveCodec, quant, 30u) ? true : false;
}
#endif

static void peer_adapt_tcp_frame_rate_from_ack(
        RDPPeerContext *ctx,
        const RDPGFX_FRAME_ACKNOWLEDGE_PDU *ack,
        uint32_t congestionThreshold) {
    if (!ctx || !ack || ctx->udpSoftSyncActive ||
        ctx->progressiveMaxFrameRate <= ctx->progressiveBaseFrameRate)
        return;

    if (ack->queueDepth == SUSPEND_FRAME_ACKNOWLEDGEMENT) {
        ctx->fpsHealthyFeedbackCount = 0u;
        ctx->fpsUnhealthyFeedbackCount = 0u;
        return;
    }

    const uint32_t lag = ctx->frameId - ack->frameId;
    const bool lagValid = (int32_t)lag >= 0;
    const uint32_t targetBytesPerSec = atomic_load_explicit(
        &ctx->progressiveTargetBytesPerSec, memory_order_acquire);
    const uint32_t baseRTTMS = atomic_load_explicit(
        &ctx->progressiveBaseRTTMS, memory_order_acquire);
    const bool healthy = lagValid && lag <= 2u &&
        ack->queueDepth < congestionThreshold &&
        baseRTTMS > 0u && baseRTTMS <= RDP_TCP_FPS_MAX_BASE_RTT_MS &&
        targetBytesPerSec >= RDP_TCP_FPS_PROMOTE_MIN_BYTES_PER_SEC;
    /* A TCP socket can report briefly non-writable while the client's ACK is
     * already current. That is ordinary flow control, not graphics pressure;
     * persistent trouble is reflected by frame lag, client queue, or the
     * adaptive byte-rate controller and is handled below. */
    const bool pressured = !lagValid || lag > 4u ||
        ack->queueDepth >= congestionThreshold ||
        targetBytesPerSec <= RDP_TCP_FPS_DEMOTE_MAX_BYTES_PER_SEC;

    if (healthy) {
        ctx->fpsUnhealthyFeedbackCount = 0u;
        if (ctx->fpsHealthyFeedbackCount < RDP_TCP_FPS_PROMOTE_ACKS)
            ctx->fpsHealthyFeedbackCount++;
        if (ctx->fpsHealthyFeedbackCount >= RDP_TCP_FPS_PROMOTE_ACKS &&
            atomic_load_explicit(&ctx->progressiveFrameRate,
                                 memory_order_acquire) <
                ctx->progressiveMaxFrameRate) {
            peer_apply_frame_rate(ctx, ctx->progressiveMaxFrameRate,
                                  "healthy low-latency TCP");
        }
        return;
    }

    ctx->fpsHealthyFeedbackCount = 0u;
    if (!pressured) {
        ctx->fpsUnhealthyFeedbackCount = 0u;
        return;
    }
    if (ctx->fpsUnhealthyFeedbackCount < RDP_TCP_FPS_DEMOTE_ACKS)
        ctx->fpsUnhealthyFeedbackCount++;
    if (ctx->fpsUnhealthyFeedbackCount >= RDP_TCP_FPS_DEMOTE_ACKS &&
        atomic_load_explicit(&ctx->progressiveFrameRate,
                             memory_order_acquire) >
            ctx->progressiveBaseFrameRate) {
        peer_apply_frame_rate(ctx, ctx->progressiveBaseFrameRate,
                              "TCP/client pressure");
    }
}

static UINT gfx_frame_acknowledge(
        RdpgfxServerContext *gfx,
        const RDPGFX_FRAME_ACKNOWLEDGE_PDU *ack) {
    if (!gfx || !ack || !gfx->custom) return ERROR_INVALID_PARAMETER;
    RDPPeerContext *ctx = (RDPPeerContext *)gfx->custom;

    atomic_store_explicit(&ctx->lastAckFrameId, ack->frameId,
                          memory_order_release);
    atomic_store_explicit(&ctx->clientQueueDepth, ack->queueDepth,
                          memory_order_relaxed);
    atomic_store_explicit(&ctx->lastAckTotalFramesDecoded,
                          ack->totalFramesDecoded, memory_order_relaxed);
    const uint64_t nowMS = GetTickCount64();
    atomic_store_explicit(&ctx->lastAckTimestampMS, nowMS,
                          memory_order_release);
    atomic_store_explicit(&ctx->lastClientResponseMS, nowMS,
                          memory_order_release);
    atomic_store_explicit(&ctx->gfxAckSeen, true, memory_order_release);
    atomic_store_explicit(&ctx->gfxAckSuspended,
                          ack->queueDepth == SUSPEND_FRAME_ACKNOWLEDGEMENT,
                          memory_order_release);

    uint32_t lastFrameBytes = atomic_load_explicit(
        &ctx->progressiveLastFrameBytes, memory_order_relaxed);
    uint32_t congestionThreshold = lastFrameBytes > 0
        ? lastFrameBytes + lastFrameBytes / 2u : 512000u;
    if (congestionThreshold < 512000u) congestionThreshold = 512000u;
    if (ack->queueDepth >= congestionThreshold &&
        ack->queueDepth != SUSPEND_FRAME_ACKNOWLEDGEMENT) {
        if (rdp_tcp_latency_force_backoff(&ctx->tcpLatency,
                                          GetTickCount64()) ==
            RDPTCPLatencyReduced) {
            atomic_store_explicit(&ctx->progressiveTargetBytesPerSec,
                                  ctx->tcpLatency.currentBytesPerSec,
                                  memory_order_release);
            rdp_info("Progressive TCP backoff: client queue=%u bytes, target=%.1f "
                     "Mbit/s", ack->queueDepth,
                     (double)ctx->tcpLatency.currentBytesPerSec * 8.0 /
                         1000000.0);
        }
    }

    peer_adapt_tcp_frame_rate_from_ack(ctx, ack, congestionThreshold);

    /* Do not log every ordinary one-frame queue report: Windows App can flush
     * hundreds of ACKs in a burst after resuming acknowledgement, and verbose
     * disk logging then becomes measurable work of its own. */
    if ((ack->frameId % 30u) == 0u ||
        ack->queueDepth == SUSPEND_FRAME_ACKNOWLEDGEMENT ||
        ack->queueDepth >= congestionThreshold) {
        rdp_info("GFX ACK: frame=%u decoded=%u client-queue=%u bytes",
                 ack->frameId, ack->totalFramesDecoded, ack->queueDepth);
    }
    return CHANNEL_RC_OK;
}

static RDPTransportFeedback peer_udp_transport_feedback(
    const RDPPeerContext *ctx, uint64_t nowMS) {
    RDPTransportFeedback feedback = {0};
    if (!ctx || !ctx->udpSoftSyncActive) return feedback;

    const uint64_t observedAtMS = atomic_load_explicit(
        &ctx->udpStatsObservedAtMS, memory_order_acquire);
    const uint64_t congestedAtMS = atomic_load_explicit(
        &ctx->udpLastCongestionMS, memory_order_acquire);
    feedback.reliableUDPActive = true;
    feedback.sampleFresh = observedAtMS && nowMS >= observedAtMS &&
        nowMS - observedAtMS <= RDP_UDP_STATS_FRESH_MS;
    feedback.recentLossOrRetransmit = congestedAtMS &&
        nowMS >= congestedAtMS &&
        nowMS - congestedAtMS <= RDP_UDP_CONGESTION_RECENT_MS;
    feedback.smoothedRTTMS = atomic_load_explicit(
        &ctx->udpSmoothedRTTMS, memory_order_relaxed);
    feedback.inflightPackets = atomic_load_explicit(
        &ctx->udpInflightPackets, memory_order_relaxed);
    feedback.congestionWindowPackets = atomic_load_explicit(
        &ctx->udpCongestionWindowPackets, memory_order_relaxed);
    feedback.queuedBytes = atomic_load_explicit(
        &ctx->udpQueuedBytes, memory_order_relaxed);
    return feedback;
}

static void peer_adapt_udp_frame_rate(
    RDPPeerContext *ctx, const RDPTransportFeedback *transport,
    uint32_t clientWorkMS) {
    if (!ctx || !transport ||
        ctx->progressiveMaxFrameRate <= ctx->progressiveBaseFrameRate)
        return;

    const uint32_t clientQueue = atomic_load_explicit(
        &ctx->clientQueueDepth, memory_order_acquire);
    const bool healthy = rdp_tcp_latency_transport_healthy(
        &ctx->tcpLatency, transport) && clientWorkMS <= 50u &&
        clientQueue == 0u;
    if (healthy) {
        ctx->fpsUnhealthyFeedbackCount = 0u;
        if (ctx->fpsHealthyFeedbackCount < RDP_UDP_FPS_PROMOTE_SAMPLES)
            ctx->fpsHealthyFeedbackCount++;
        if (ctx->fpsHealthyFeedbackCount >= RDP_UDP_FPS_PROMOTE_SAMPLES &&
            atomic_load_explicit(&ctx->progressiveFrameRate,
                                 memory_order_acquire) <
                ctx->progressiveMaxFrameRate) {
            peer_apply_frame_rate(ctx, ctx->progressiveMaxFrameRate,
                                  "healthy reliable UDP");
        }
        return;
    }

    ctx->fpsHealthyFeedbackCount = 0u;
    if (ctx->fpsUnhealthyFeedbackCount < RDP_UDP_FPS_DEMOTE_SAMPLES)
        ctx->fpsUnhealthyFeedbackCount++;
    if (ctx->fpsUnhealthyFeedbackCount >= RDP_UDP_FPS_DEMOTE_SAMPLES &&
        atomic_load_explicit(&ctx->progressiveFrameRate,
                             memory_order_acquire) >
            ctx->progressiveBaseFrameRate) {
        peer_apply_frame_rate(ctx, ctx->progressiveBaseFrameRate,
                              "UDP/client pressure");
    }
}

static const char *latency_adjustment_cause_name(
    RDPTCPLatencyCause cause) {
    switch (cause) {
        case RDPTCPLatencyCauseNetwork: return "network";
        case RDPTCPLatencyCauseClient: return "client-render";
        case RDPTCPLatencyCauseClientQueue: return "client-queue";
        default: return "stable";
    }
}

static UINT gfx_qoe_frame_acknowledge(
        RdpgfxServerContext *gfx,
        const RDPGFX_QOE_FRAME_ACKNOWLEDGE_PDU *qoe) {
    if (!gfx || !qoe || !gfx->custom) return ERROR_INVALID_PARAMETER;
    RDPPeerContext *ctx = (RDPPeerContext *)gfx->custom;
    const uint64_t nowMS = GetTickCount64();
    atomic_store_explicit(&ctx->lastClientResponseMS, nowMS,
                          memory_order_release);
    const uint32_t slot = qoe->frameId % RDP_QOE_SEND_HISTORY;
    uint32_t feedbackMS = 0;
    uint32_t frameBytes = 0;
    if (atomic_load_explicit(&ctx->qoeSendFrameIds[slot],
                             memory_order_acquire) == qoe->frameId) {
        const uint64_t sentMS = atomic_load_explicit(
            &ctx->qoeSendTimesMS[slot], memory_order_relaxed);
        frameBytes = atomic_load_explicit(&ctx->qoeSendSizes[slot],
                                          memory_order_relaxed);
        if (sentMS && nowMS >= sentMS && nowMS - sentMS <= UINT32_MAX)
            feedbackMS = (uint32_t)(nowMS - sentMS);
    }
    const uint32_t previousQoeFrame = atomic_load_explicit(
        &ctx->lastQoeFrameId, memory_order_relaxed);
    if ((int32_t)(qoe->frameId - previousQoeFrame) >= 0) {
        atomic_store_explicit(&ctx->lastQoeFrameId, qoe->frameId,
                              memory_order_relaxed);
        atomic_store_explicit(&ctx->lastQoeClientTimestampMS, qoe->timestamp,
                              memory_order_relaxed);
        atomic_store_explicit(&ctx->lastQoeDecodeSpanMS, qoe->timeDiffSE,
                              memory_order_relaxed);
        atomic_store_explicit(&ctx->lastQoeRenderMS, qoe->timeDiffEDR,
                              memory_order_relaxed);
        atomic_store_explicit(&ctx->lastQoeFeedbackMS, feedbackMS,
                              memory_order_release);
    }
    /* Publish the completed QoE sample after all of its fields. The capture
     * thread acquires qoeAckCount before consulting lastQoeFrameId. */
    const uint64_t count = atomic_fetch_add_explicit(&ctx->qoeAckCount, 1,
                                                      memory_order_release) + 1u;
    const RDPTransportFeedback transport = peer_udp_transport_feedback(
        ctx, nowMS);
    const RDPTCPLatencyAdjustment adjustment =
        rdp_tcp_latency_on_feedback_with_transport(
            &ctx->tcpLatency, feedbackMS, frameBytes, qoe->timeDiffSE,
            qoe->timeDiffEDR, &transport, count, nowMS);
    peer_adapt_udp_frame_rate(ctx, &transport,
                              (uint32_t)qoe->timeDiffSE + qoe->timeDiffEDR);
    if (adjustment != RDPTCPLatencyUnchanged) {
        const char *adjustmentName = "recovery";
        if (adjustment == RDPTCPLatencyReduced)
            adjustmentName = "backoff";
        else if (adjustment == RDPTCPLatencyProbed)
            adjustmentName = "upward-probe";
        atomic_store_explicit(&ctx->progressiveTargetBytesPerSec,
                              ctx->tcpLatency.currentBytesPerSec,
                              memory_order_release);
        rdp_info("Progressive %s feedback %s: reason=%s sample=%u ms "
                 "smoothed=%u ms target=%.1f/%.1f Mbit/s confirmed=%.1f "
                 "Mbit/s transport-rtt=%ums inflight=%u/%u queued=%u",
                 transport.reliableUDPActive ? "UDP" : "TCP",
                 adjustmentName,
                 latency_adjustment_cause_name(
                     ctx->tcpLatency.lastAdjustmentCause),
                 feedbackMS, ctx->tcpLatency.smoothedFeedbackMS,
                 (double)ctx->tcpLatency.currentBytesPerSec * 8.0 / 1000000.0,
                 (double)ctx->tcpLatency.measuredCeilingBytesPerSec * 8.0 /
                     1000000.0,
                 (double)ctx->tcpLatency.confirmedCeilingBytesPerSec * 8.0 /
                     1000000.0,
                 transport.smoothedRTTMS, transport.inflightPackets,
                 transport.congestionWindowPackets, transport.queuedBytes);
    }
    const uint32_t activeFrameRate = atomic_load_explicit(
        &ctx->progressiveFrameRate, memory_order_acquire);
    const uint32_t cadence = activeFrameRate ? activeFrameRate : 30u;
    if ((count % cadence) == 0u || qoe->timeDiffSE >= 50u ||
        qoe->timeDiffEDR >= 50u || adjustment != RDPTCPLatencyUnchanged) {
        rdp_info("GFX QoE: frame=%u bytes=%u client-ts=%u feedback=%ums "
                 "smoothed=%ums decode-span=%ums render=%ums",
                 qoe->frameId, frameBytes, qoe->timestamp, feedbackMS,
                 ctx->tcpLatency.smoothedFeedbackMS, qoe->timeDiffSE,
                 qoe->timeDiffEDR);
    }
    return CHANNEL_RC_OK;
}

static BOOL gfx_channel_id_assigned(RdpgfxServerContext *gfx, UINT32 channelId) {
    if (!gfx || !gfx->custom || !channelId) return FALSE;
    RDPPeerContext *ctx = (RDPPeerContext *)gfx->custom;
    ctx->gfxChannelId = channelId;
    rdp_info("GFX dynamic channel assigned id %u", channelId);
    return TRUE;
}

static void progressive_release_surface_state(RDPPeerContext *ctx) {
    if (!ctx) return;
    if (ctx->progressiveCodec) {
        progressive_context_free((PROGRESSIVE_CONTEXT *)ctx->progressiveCodec);
        ctx->progressiveCodec = NULL;
    }
    free(ctx->progressiveReferencePixels);
    free(ctx->progressiveTileMask);
    free(ctx->progressiveLowQualityTiles);
    ctx->progressiveReferencePixels = NULL;
    ctx->progressiveTileMask = NULL;
    ctx->progressiveLowQualityTiles = NULL;
    ctx->progressiveReferenceSize = 0;
    ctx->progressiveReferenceStride = 0;
    ctx->progressiveTileColumns = 0;
    ctx->progressiveTileRows = 0;
    ctx->progressiveRefinementCursor = 0;
    ctx->progressiveRefinementBatches = 0;
    atomic_store_explicit(&ctx->progressiveLastFrameBytes, 0u,
                          memory_order_release);
    atomic_store_explicit(&ctx->progressiveLastFrameTiles, 0u,
                          memory_order_release);
    ctx->progressiveReferenceValid = false;
}

static bool progressive_prepare_surface_state(RDPPeerContext *ctx,
                                              uint32_t width,
                                              uint32_t height) {
    if (!ctx || !width || !height) return false;
    progressive_release_surface_state(ctx);

    ctx->progressiveCodec = progressive_context_new(TRUE);
    if (!ctx->progressiveCodec ||
        progressive_create_surface_context(
            (PROGRESSIVE_CONTEXT *)ctx->progressiveCodec,
            (UINT16)ctx->surfaceId, width, height) < 0) {
        rdp_error("failed to initialize RemoteFX Progressive surface");
        progressive_release_surface_state(ctx);
        return false;
    }

    size_t refStride = (size_t)width * 4u;
    size_t refSize = refStride * (size_t)height;
    uint32_t tileColumns = (width + 63u) / 64u;
    uint32_t tileRows = (height + 63u) / 64u;
    size_t tileCount = (size_t)tileColumns * (size_t)tileRows;
    if (!refStride || refStride / 4u != width || !refSize ||
        refSize / refStride != height || !tileCount)
        return true; /* Codec remains usable without exact tile filtering. */

    ctx->progressiveReferencePixels = (uint8_t *)calloc(1, refSize);
    ctx->progressiveTileMask = (uint8_t *)calloc(tileCount, 1);
    ctx->progressiveLowQualityTiles = (uint8_t *)calloc(tileCount, 1);
    if (!ctx->progressiveReferencePixels || !ctx->progressiveTileMask ||
        !ctx->progressiveLowQualityTiles) {
        free(ctx->progressiveReferencePixels);
        free(ctx->progressiveTileMask);
        free(ctx->progressiveLowQualityTiles);
        ctx->progressiveReferencePixels = NULL;
        ctx->progressiveTileMask = NULL;
        ctx->progressiveLowQualityTiles = NULL;
        rdp_error("Progressive tile state allocation failed; metadata-only damage");
        return true;
    }

    ctx->progressiveReferenceSize = refSize;
    ctx->progressiveReferenceStride = (uint32_t)refStride;
    ctx->progressiveTileColumns = tileColumns;
    ctx->progressiveTileRows = tileRows;
    ctx->progressiveRefinementCursor = 0;
    ctx->progressiveRefinementBatches = 0;
    ctx->progressiveReferenceValid = false;
    rdp_info("Progressive tile state ready: %ux%u tiles, %.1f MiB reference",
             tileColumns, tileRows, (double)refSize / (1024.0 * 1024.0));
    return true;
}

static UINT gfx_create_and_map_surface(RDPPeerContext *ctx,
                                       uint32_t width, uint32_t height) {
    if (!ctx || !ctx->gfx || !width || !height ||
        width > UINT16_MAX || height > UINT16_MAX)
        return ERROR_INVALID_PARAMETER;

    RDPGFX_CREATE_SURFACE_PDU cs = {0};
    cs.surfaceId = ctx->surfaceId;
    cs.width = (UINT16)width;
    cs.height = (UINT16)height;
    cs.pixelFormat = GFX_PIXEL_FORMAT_XRGB_8888;
    UINT rc = ctx->gfx->CreateSurface(ctx->gfx, &cs);
    if (rc != CHANNEL_RC_OK) return rc;

    RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU ms = {0};
    ms.surfaceId = ctx->surfaceId;
    rc = ctx->gfx->MapSurfaceToOutput(ctx->gfx, &ms);
    if (rc == CHANNEL_RC_OK) {
        ctx->surfaceWidth = width;
        ctx->surfaceHeight = height;
    }
    return rc;
}

static void peer_apply_frame_rate(RDPPeerContext *ctx, uint32_t frameRate,
                                  const char *reason) {
    if (!ctx || !frameRate) return;
    uint32_t prior = atomic_load_explicit(&ctx->progressiveFrameRate,
                                          memory_order_relaxed);
    uint32_t intervalMS = 1000u / frameRate;
    if (!intervalMS) intervalMS = 1u;
    atomic_store_explicit(&ctx->progressiveFrameRate, frameRate,
                          memory_order_release);
    atomic_store_explicit(&ctx->progressiveFrameIntervalMS, intervalMS,
                          memory_order_release);
    ctx->progressiveMaxQoeInflight = rdp_tcp_latency_set_frame_interval(
        &ctx->tcpLatency, intervalMS);
    if (ctx->callbacks.onFrameRateChange)
        ctx->callbacks.onFrameRateChange(ctx->callbacks.userdata, frameRate);
    if (prior && prior != frameRate)
        rdp_info("graphics refresh target: %u -> %u fps (%s)", prior,
                 frameRate, reason ? reason : "transport update");
}

static void peer_update_frame_timing(RDPPeerContext *ctx,
                                     uint32_t width, uint32_t height) {
    ctx->progressiveBaseFrameRate = progressive_frame_rate(width, height);
    ctx->progressiveMaxFrameRate = progressive_max_frame_rate(
        width, height, ctx->progressiveBaseFrameRate);
    ctx->fpsHealthyFeedbackCount = 0u;
    ctx->fpsUnhealthyFeedbackCount = 0u;
    peer_apply_frame_rate(ctx, ctx->progressiveBaseFrameRate,
                          "resolution baseline");
}

static UINT disp_monitor_layout(DispServerContext *disp,
                                const DISPLAY_CONTROL_MONITOR_LAYOUT_PDU *pdu) {
    RDPPeerContext *ctx = disp ? (RDPPeerContext *)disp->custom : NULL;
    if (!ctx || !pdu || !pdu->Monitors || pdu->NumMonitors == 0 ||
        pdu->NumMonitors > disp->MaxNumMonitors)
        return ERROR_INVALID_DATA;

    int64_t minLeft = INT64_MAX, minTop = INT64_MAX;
    int64_t maxRight = INT64_MIN, maxBottom = INT64_MIN;
    for (UINT32 i = 0; i < pdu->NumMonitors; i++) {
        const DISPLAY_CONTROL_MONITOR_LAYOUT *m = &pdu->Monitors[i];
        int64_t right = (int64_t)m->Left + m->Width;
        int64_t bottom = (int64_t)m->Top + m->Height;
        if (m->Left < minLeft) minLeft = m->Left;
        if (m->Top < minTop) minTop = m->Top;
        if (right > maxRight) maxRight = right;
        if (bottom > maxBottom) maxBottom = bottom;
    }
    int64_t spanWidth = maxRight - minLeft;
    int64_t spanHeight = maxBottom - minTop;
    if (spanWidth < DISPLAY_CONTROL_MIN_MONITOR_WIDTH ||
        spanWidth > DISPLAY_CONTROL_MAX_MONITOR_WIDTH ||
        spanHeight < DISPLAY_CONTROL_MIN_MONITOR_HEIGHT ||
        spanHeight > DISPLAY_CONTROL_MAX_MONITOR_HEIGHT ||
        (spanWidth & 1) != 0)
        return ERROR_INVALID_DATA;

    uint64_t packed = ((uint64_t)(uint32_t)spanWidth << 32) |
                      (uint32_t)spanHeight;
    atomic_store_explicit(&ctx->pendingDisplaySize, packed,
                          memory_order_release);
    rdp_info("RDPEDISP layout queued: %u monitor(s), desktop=%lldx%lld",
             pdu->NumMonitors, (long long)spanWidth, (long long)spanHeight);
    return CHANNEL_RC_OK;
}

/* Recreate only the client-side RDPGFX surface. The BetterDisplay instance,
 * logged-in macOS desktop, capture session ownership, and authentication state
 * all remain intact. Caller owns xportLock so no stateful Progressive frame can
 * interleave with DeleteSurface/ResetGraphics/CreateSurface/MapSurface. */
static bool peer_reset_gfx_surface_locked(RDPPeerContext *ctx,
                                          uint32_t width,
                                          uint32_t height,
                                          const char *reason) {
    if (!ctx || !ctx->gfx || !ctx->gfxReady || !width || !height)
        return false;

    ctx->outputSuppressed = true;
    RDPGFX_DELETE_SURFACE_PDU del = { .surfaceId = (UINT16)ctx->surfaceId };
    UINT rc = ctx->gfx->DeleteSurface(ctx->gfx, &del);
    if (rc != CHANNEL_RC_OK)
        rdp_verbose("%s DeleteSurface returned %u; continuing reset",
                    reason ? reason : "RDPGFX", rc);

    MONITOR_DEF monitor = {
        .left = 0, .top = 0,
        .right = (INT32)width - 1,
        .bottom = (INT32)height - 1,
        .flags = DISPLAY_CONTROL_MONITOR_PRIMARY,
    };
    RDPGFX_RESET_GRAPHICS_PDU reset = {
        .width = width,
        .height = height,
        .monitorCount = 1,
        .monitorDefArray = &monitor,
    };
    rc = ctx->gfx->ResetGraphics(ctx->gfx, &reset);
    if (rc != CHANNEL_RC_OK) {
        rdp_error("%s ResetGraphics failed: %u",
                  reason ? reason : "RDPGFX", rc);
        ctx->outputSuppressed = false;
        return false;
    }
    rc = gfx_create_and_map_surface(ctx, width, height);
    if (rc != CHANNEL_RC_OK) {
        rdp_error("%s Create/Map surface failed: %u",
                  reason ? reason : "RDPGFX", rc);
        ctx->outputSuppressed = false;
        return false;
    }

    if (ctx->graphicsMode == RDPGraphicsModeProgressive &&
        !progressive_prepare_surface_state(ctx, width, height)) {
        ctx->outputSuppressed = false;
        return false;
    }

    /* Keep frame IDs monotonic across the reset. A late ACK from the previous
     * surface must not underflow the QoE/backpressure sequence arithmetic. */
    atomic_store_explicit(&ctx->lastAckFrameId, ctx->frameId,
                          memory_order_release);
    atomic_store_explicit(&ctx->lastQoeFrameId, ctx->frameId,
                          memory_order_release);
    atomic_store_explicit(&ctx->gfxAckSeen, false, memory_order_release);
    ctx->progressiveNextSendMS = 0u;
    if (ctx->progressivePendingRegionInitialized)
        region16_clear(&ctx->progressivePendingRegion);
    peer_update_frame_timing(ctx, width, height);
    ctx->sentKeyframe = false;
    ctx->keyframeRequested = false;
    ctx->outputSuppressed = false;
    if (ctx->graphicsMode == RDPGraphicsModeAVC420 &&
        ctx->callbacks.onKeyframeRequest) {
        ctx->keyframeRequested = true;
        ctx->callbacks.onKeyframeRequest(ctx->callbacks.userdata);
    }
    rdp_info("%s RDPGFX surface resynchronized: %ux%u (desktop retained)",
             reason ? reason : "RDPGFX", width, height);
    return true;
}

static bool peer_apply_pending_graphics_resync_locked(RDPPeerContext *ctx) {
    if (!atomic_exchange_explicit(&ctx->pendingGraphicsResync, false,
                                  memory_order_acq_rel))
        return true;
    if (!ctx->gfxReady || !ctx->gfx) {
        rdp_verbose("foreground RDPGFX resync skipped before graphics ready");
        return true;
    }
    return peer_reset_gfx_surface_locked(ctx, ctx->surfaceWidth,
                                         ctx->surfaceHeight,
                                         "foreground recovery");
}

static bool peer_apply_pending_display_resize(freerdp_peer *peer,
                                              RDPPeerContext *ctx) {
    uint64_t packed = atomic_exchange_explicit(&ctx->pendingDisplaySize, 0,
                                               memory_order_acq_rel);
    if (!packed) return true;
    uint32_t width = (uint32_t)(packed >> 32);
    uint32_t height = (uint32_t)packed;
    if (width == ctx->surfaceWidth && height == ctx->surfaceHeight)
        return true;

    if (!ctx->callbacks.onDisplayResize ||
        !ctx->callbacks.onDisplayResize(ctx->callbacks.userdata, width, height)) {
        rdp_error("RDPEDISP resize rejected by macOS display: %ux%u", width, height);
        return true; /* A rejected layout does not terminate the RDP session. */
    }

    bool ok = true;
    pthread_mutex_lock(&ctx->xportLock);
    rdpSettings *settings = peer->context->settings;
    if (!freerdp_settings_set_uint32(settings, FreeRDP_DesktopWidth, width) ||
        !freerdp_settings_set_uint32(settings, FreeRDP_DesktopHeight, height)) {
        ok = false;
        goto out;
    }

    if (!ctx->gfxReady || !ctx->gfx) {
        ctx->surfaceWidth = width;
        ctx->surfaceHeight = height;
        goto out;
    }

    ok = peer_reset_gfx_surface_locked(ctx, width, height, "RDPEDISP resize");
out:
    pthread_mutex_unlock(&ctx->xportLock);
    return ok;
}

static UINT gfx_caps_advertise(RdpgfxServerContext *gfx,
                                const RDPGFX_CAPS_ADVERTISE_PDU *pdu) {
    RDPPeerContext *ctx = (RDPPeerContext *)gfx->custom;
    rdp_verbose("GFX caps advertise: %u sets", pdu->capsSetCount);

    /* Stack-allocate the capset — capsSet is a pointer in 3.x. */
    RDPGFX_CAPSET capset = {0};
    RDPGFX_CAPSET bestAvc = {0};
    RDPGFX_CAPSET bestAny = {0};
    RDPGFX_CAPS_CONFIRM_PDU confirm = {0};
    confirm.capsSet = &capset;

    /* Walk every advertised set. "auto" only selects AVC when the exact set
     * advertises it; otherwise it uses Progressive. "force-avc" confirms an
     * advertised set verbatim but deliberately violates its AVC_DISABLED bit
     * when frames are sent, solely to test whether this Windows App build has a
     * dormant decoder. Never clear or invent capability flags in CapsConfirm. */
    for (UINT16 i = 0; i < pdu->capsSetCount; i++) {
        rdp_verbose("  caps[%u] version=0x%08x flags=0x%08x",
                    i, pdu->capsSets[i].version, pdu->capsSets[i].flags);
        if (pdu->capsSets[i].version >= RDPGFX_CAPVERSION_8 &&
            pdu->capsSets[i].version >= bestAny.version)
            bestAny = pdu->capsSets[i];
        if (capset_supports_avc(&pdu->capsSets[i]) &&
            pdu->capsSets[i].version >= bestAvc.version)
            bestAvc = pdu->capsSets[i];
    }

    const char *policy = graphics_policy();
    if (strcmp(policy, "force-avc") == 0) {
        capset = bestAvc.version ? bestAvc : bestAny;
        ctx->graphicsMode = RDPGraphicsModeAVC420;
        if (!bestAvc.version)
            rdp_error("UNSAFE TEST: client advertised AVC_DISABLED in every capset; "
                      "force-avc will still transmit AVC420");
    } else if (strcmp(policy, "progressive") == 0) {
        capset = bestAny;
        ctx->graphicsMode = RDPGraphicsModeProgressive;
    } else {
        capset = bestAvc.version ? bestAvc : bestAny;
        ctx->graphicsMode = bestAvc.version ? RDPGraphicsModeAVC420
                                            : RDPGraphicsModeProgressive;
    }

    if (!capset.version) {
        rdp_error("client advertised no usable GFX caps version");
        return ERROR_INTERNAL_ERROR;
    }
    rdp_info("GFX policy=%s mode=%s confirm version=0x%08x flags=0x%08x",
             policy,
             ctx->graphicsMode == RDPGraphicsModeAVC420 ? "AVC420" : "Progressive",
             capset.version, capset.flags);

    UINT rc = gfx->CapsConfirm(gfx, &confirm);
    if (rc != CHANNEL_RC_OK) { rdp_error("CapsConfirm failed: %u", rc); return rc; }

    rdpSettings *s = ctx->base.peer->context->settings;
    UINT32 w = freerdp_settings_get_uint32(s, FreeRDP_DesktopWidth);
    UINT32 h = freerdp_settings_get_uint32(s, FreeRDP_DesktopHeight);

    /* NOTE: we deliberately do NOT send RDPGFX_RESET_GRAPHICS. Field testing showed
     * mstsc resets the connection ~10ms after receiving our RESET_GRAPHICS PDU
     * (before any surface frame), whereas without it the session is stable. The
     * surface is created at the full desktop size and mapped to output origin (0,0),
     * which mstsc composites against the negotiated desktop dimensions directly.
     * (The earlier black screen was the P-frame-before-keyframe bug, since fixed,
     * not a missing canvas.) If multi-monitor support is added later, RESET_GRAPHICS
     * will be needed — but the MONITOR_DEF format must be validated against mstsc. */

    rc = gfx_create_and_map_surface(ctx, w, h);
    if (rc != CHANNEL_RC_OK) {
        rdp_error("initial Create/Map surface failed: %u", rc);
        return rc;
    }

    ctx->gfxReady = true;
    peer_update_frame_timing(ctx, w, h);
    rdp_info("graphics refresh target: %u fps (%u ms minimum interval), "
             "LAN/UDP ceiling=%u fps, rendered-frame backlog=%u",
             atomic_load_explicit(&ctx->progressiveFrameRate,
                                  memory_order_acquire),
             atomic_load_explicit(&ctx->progressiveFrameIntervalMS,
                                  memory_order_acquire),
             ctx->progressiveMaxFrameRate,
             ctx->progressiveMaxQoeInflight);

    if (ctx->graphicsMode == RDPGraphicsModeProgressive) {
        if (!progressive_prepare_surface_state(ctx, w, h))
            return ERROR_INTERNAL_ERROR;
    } else {
        /* Any frames encoded during GFX setup were dropped ("gfx not ready"),
         * so demand a fresh IDR as the first transmitted AVC frame. */
        ctx->sentKeyframe = false;
        if (ctx->callbacks.onKeyframeRequest) {
            ctx->keyframeRequested = true;
            ctx->callbacks.onKeyframeRequest(ctx->callbacks.userdata);
        }
    }
    rdp_info("GFX pipeline ready (%ux%u %s)", w, h,
             ctx->graphicsMode == RDPGraphicsModeAVC420 ? "AVC420" : "Progressive");
    return CHANNEL_RC_OK;
}

/* ── Clipboard callbacks ───────────────────────────────────────────────── */

/* xportLock must already be held. Defined with the public send helpers. */
static UINT clipboard_advertise_locked(RDPPeerContext *ctx, uint32_t format,
                                       const char *formatName);

/* The client sent us ITS Clipboard Capabilities (MS-RDPECLIP step 3). This is
 * the first proof mstsc accepted our caps + monitor-ready and is engaging the
 * channel. We just log it; the channel layer has already latched the negotiated
 * flags (e.g. useLongFormatNames) onto the context. */
static UINT cliprdr_client_capabilities(CliprdrServerContext *cliprdr,
                                        const CLIPRDR_CAPABILITIES *caps) {
    RDPPeerContext *ctx = (RDPPeerContext *)cliprdr->custom;
    /* Client engaged the channel — it is now safe to advertise (ServerFormatList). */
    if (ctx) ctx->clipReady = true;
    UINT32 flags = 0, version = 0;
    for (UINT32 i = 0; i < caps->cCapabilitiesSets; i++) {
        const CLIPRDR_CAPABILITY_SET *set = &caps->capabilitySets[i];
        if (set->capabilitySetType == CB_CAPSTYPE_GENERAL) {
            const CLIPRDR_GENERAL_CAPABILITY_SET *g =
                (const CLIPRDR_GENERAL_CAPABILITY_SET *)set;
            version = g->version;
            flags   = g->generalFlags;
        }
    }
    rdp_info("clipboard ready: client sets=%u version=0x%08x flags=0x%08x "
             "longNames=%d fileStreams=%d",
             caps->cCapabilitiesSets, version, flags,
             (flags & CB_USE_LONG_FORMAT_NAMES) ? 1 : 0,
             (flags & CB_STREAM_FILECLIP_ENABLED) ? 1 : 0);

    /* A Finder copy can race this initialization sequence. The send helpers
     * retain the newest payload while clipReady is false, so publish it now. */
    if (ctx && ctx->clipData && ctx->clipLen > 0) {
        const bool isFiles =
            ctx->clipFormat == RDP_CLIPBOARD_FORMAT_FILE_GROUP_DESCRIPTOR_W;
        if (!isFiles || cliprdr->streamFileClipEnabled) {
            const char *name = isFiles ? "FileGroupDescriptorW" :
                               (ctx->clipFormat == RDP_CLIPBOARD_FORMAT_PNG
                                    ? "PNG" : "");
            UINT rc = clipboard_advertise_locked(ctx, ctx->clipFormat, name);
            rdp_info("clipboard: published deferred format 0x%08x "
                     "(%zu bytes, rc=%u)", ctx->clipFormat, ctx->clipLen, rc);
        } else {
            rdp_info("clipboard: deferred file copy cannot be published; "
                     "client did not negotiate file streams");
        }
    }
    return CHANNEL_RC_OK;
}

/* The client ACKed our Format List (our Mac->Win advertise). On success it will
 * follow up with a Format Data Request when the user pastes on Windows. */
static UINT cliprdr_client_format_list_response(
        CliprdrServerContext *cliprdr,
        const CLIPRDR_FORMAT_LIST_RESPONSE *resp) {
    (void)cliprdr;
    rdp_info("clipboard: client %s the advertised format list",
             (resp->common.msgFlags & CB_RESPONSE_OK) ? "accepted" : "rejected");
    return CHANNEL_RC_OK;
}

/* Windows copied something: the client advertises the formats it now holds. We
 * ACK the list, then pull either FileGroupDescriptorW (preferred for a file copy)
 * or the best text representation. The client never pushes payloads unsolicited. */
static UINT cliprdr_client_format_list(CliprdrServerContext *cliprdr,
                                        const CLIPRDR_FORMAT_LIST *list) {
    RDPPeerContext *ctx = (RDPPeerContext *)cliprdr->custom;
    ctx->clipReady = true;   /* channel fully engaged — Mac->Win advertise is safe */
    /* A new remote clipboard supersedes any previous download/published staging
     * set. If it was already published, Finder sees the same clipboard change and
     * no longer needs the old paths. */
    clipboard_incoming_reset(ctx, true);
    ctx->clipReqIsFileList = false;
    rdp_verbose("clipboard: <- ClientFormatList (%u formats)", list->numFormats);
    for (UINT32 i = 0; i < list->numFormats; i++)
        rdp_verbose("clipboard:    format[%u] id=0x%08x name=%s", i,
                    list->formats[i].formatId,
                    list->formats[i].formatName ? list->formats[i].formatName : "(none)");

    /* Acknowledge the advertisement first (msgType is set by the server serializer,
     * but a Format List RESPONSE carries CB_RESPONSE_OK in msgFlags). */
    CLIPRDR_FORMAT_LIST_RESPONSE resp = {0};
    resp.common.msgType  = CB_FORMAT_LIST_RESPONSE;
    resp.common.msgFlags = CB_RESPONSE_OK;
    cliprdr->ServerFormatListResponse(cliprdr, &resp);

    /* Choose files before text. Finder file copies often also expose a path-like
     * CF_UNICODETEXT value, which must not mask the real stream-backed format. */
    UINT32 fileWant = 0;
    UINT32 textWant = 0;
    for (UINT32 i = 0; i < list->numFormats; i++) {
        UINT32 id = list->formats[i].formatId;
        const char *name = list->formats[i].formatName;
        if (name && strcmp(name, "FileGroupDescriptorW") == 0)
            fileWant = id;
        if (id == CF_UNICODETEXT)
            textWant = CF_UNICODETEXT;
        else if (id == CF_TEXT && textWant == 0)
            textWant = CF_TEXT;
    }
    UINT32 want = (fileWant && cliprdr->streamFileClipEnabled)
        ? fileWant : textWant;
    if (!want) {
        rdp_info("clipboard: client offered no supported text or file format");
        return CHANNEL_RC_OK;
    }

    /* Request the bytes. The response (cliprdr_client_format_data) has no format
     * id of its own, so stash what we asked for. */
    ctx->clipReqFormat = want;
    ctx->clipReqIsFileList = (want == fileWant && fileWant != 0);
    CLIPRDR_FORMAT_DATA_REQUEST dreq = {0};
    dreq.common.msgType   = CB_FORMAT_DATA_REQUEST;
    /* dataLen MUST be 4: FreeRDP's cliprdr_server_format_data_request allocates a
     * stream of (common.dataLen + 8) and then writes the 4-byte requestedFormatId
     * AFTER the 8-byte header. With dataLen=0 the stream is exactly the header and
     * the formatId write runs off the end -> WinPR Stream_Write_UINT32 abort (the
     * crash that locked the client out on every connect). */
    dreq.common.dataLen   = 4;
    dreq.requestedFormatId = want;
    rdp_info("clipboard: requesting %s format 0x%08x from client",
             ctx->clipReqIsFileList ? "file-list" : "text", want);
    cliprdr->ServerFormatDataRequest(cliprdr, &dreq);
    return CHANNEL_RC_OK;
}

/* The client answered our Format Data Request: hand the bytes to the Mac
 * pasteboard via the onClipboard callback. The response carries no format id, so
 * we use the one we requested (clipReqFormat). */
static UINT cliprdr_client_format_data(CliprdrServerContext *cliprdr,
                                        const CLIPRDR_FORMAT_DATA_RESPONSE *resp) {
    RDPPeerContext *ctx = (RDPPeerContext *)cliprdr->custom;
    rdp_verbose("clipboard: <- ClientFormatDataResponse (flags=0x%04x len=%u)",
                resp->common.msgFlags, resp->common.dataLen);
    if (ctx->clipReqIsFileList) {
        ctx->clipReqIsFileList = false;
        if ((resp->common.msgFlags & CB_RESPONSE_OK) &&
            clipboard_incoming_begin(ctx, resp->requestedFormatData,
                                     resp->common.dataLen)) {
            return CHANNEL_RC_OK;
        }
        rdp_info("clipboard: client file-list response could not be accepted");
        clipboard_incoming_reset(ctx, true);
        return CHANNEL_RC_OK;
    }

    if ((resp->common.msgFlags & CB_RESPONSE_OK) && ctx->callbacks.onClipboard) {
        rdp_verbose("clipboard: %u bytes from client (format 0x%08x)",
                    resp->common.dataLen, ctx->clipReqFormat);
        ctx->callbacks.onClipboard(ctx->callbacks.userdata,
                                   resp->requestedFormatData,
                                   resp->common.dataLen,
                                   ctx->clipReqFormat ? ctx->clipReqFormat
                                                      : (UINT32)CF_UNICODETEXT);
    } else {
        rdp_verbose("clipboard: client format-data response failed (flags=0x%04x)",
                    resp->common.msgFlags);
    }
    return CHANNEL_RC_OK;
}

/* One response to the sequential client -> Mac file range request. Keeping only
 * one request outstanding makes stream-id validation strict and bounds memory to
 * a single 64 KiB chunk. The callback runs under xportLock. */
static UINT cliprdr_client_file_contents_response(
        CliprdrServerContext *cliprdr,
        const CLIPRDR_FILE_CONTENTS_RESPONSE *resp) {
    RDPPeerContext *ctx = (RDPPeerContext *)cliprdr->custom;
    if (!ctx || !ctx->clipIncomingActive ||
        resp->streamId != ctx->clipIncomingExpectedStreamId ||
        ctx->clipIncomingIndex >= ctx->clipIncomingCount) {
        rdp_info("clipboard: ignored unexpected file response stream=%u",
                 resp->streamId);
        return CHANNEL_RC_OK;
    }

    const uint64_t size = ctx->clipIncomingSizes[ctx->clipIncomingIndex];
    const uint64_t remaining = size - ctx->clipIncomingOffset;
    if (!(resp->common.msgFlags & CB_RESPONSE_OK) ||
        !resp->requestedData || resp->cbRequested == 0 ||
        resp->cbRequested > ctx->clipIncomingRequestedBytes ||
        (uint64_t)resp->cbRequested > remaining) {
        rdp_info("clipboard: invalid/failed file response stream=%u len=%u",
                 resp->streamId, resp->cbRequested);
        clipboard_incoming_reset(ctx, true);
        return CHANNEL_RC_OK;
    }

    size_t offset = 0;
    while (offset < resp->cbRequested) {
        ssize_t wrote = write(ctx->clipIncomingFD,
                              resp->requestedData + offset,
                              resp->cbRequested - offset);
        if (wrote > 0) {
            offset += (size_t)wrote;
            continue;
        }
        if (wrote < 0 && errno == EINTR) continue;
        rdp_info("clipboard: writing staged file failed: %s", strerror(errno));
        clipboard_incoming_reset(ctx, true);
        return CHANNEL_RC_OK;
    }

    ctx->clipIncomingOffset += resp->cbRequested;
    ctx->clipIncomingExpectedStreamId = 0;
    ctx->clipIncomingRequestedBytes = 0;
    if (ctx->clipIncomingOffset == size) {
        close(ctx->clipIncomingFD);
        ctx->clipIncomingFD = -1;
        rdp_info("clipboard: downloaded Windows file %u/%u (%llu bytes)",
                 ctx->clipIncomingIndex + 1, ctx->clipIncomingCount,
                 (unsigned long long)size);
        ctx->clipIncomingIndex++;
        ctx->clipIncomingOffset = 0;
    }
    clipboard_incoming_request_next(ctx);
    return CHANNEL_RC_OK;
}

/* Client pasted: it requests the bytes for a format we advertised. Reply with
 * the held host data (or an empty failure response if we have none). */
static UINT cliprdr_client_format_data_request(
        CliprdrServerContext *cliprdr,
        const CLIPRDR_FORMAT_DATA_REQUEST *req) {
    RDPPeerContext *ctx = (RDPPeerContext *)cliprdr->custom;
    CLIPRDR_FORMAT_DATA_RESPONSE resp = {0};
    rdp_info("clipboard: client requested format 0x%08x",
             req->requestedFormatId);

    if (ctx->clipData && ctx->clipLen > 0 &&
        req->requestedFormatId == ctx->clipFormat) {
        resp.common.msgFlags     = CB_RESPONSE_OK;
        resp.common.dataLen      = (UINT32)ctx->clipLen;
        resp.requestedFormatData = (BYTE *)ctx->clipData;
        rdp_verbose("clipboard: serving %zu bytes for format 0x%08x",
                    ctx->clipLen, req->requestedFormatId);
    } else {
        resp.common.msgFlags = CB_RESPONSE_FAIL;
        rdp_verbose("clipboard: data request 0x%08x but nothing matching held "
                    "(have format 0x%08x, %zu bytes)",
                    req->requestedFormatId, ctx->clipFormat, ctx->clipLen);
    }
    cliprdr->ServerFormatDataResponse(cliprdr, &resp);
    return CHANNEL_RC_OK;
}

/* The client pasted a Mac file. FileGroupDescriptorW supplies metadata only;
 * Windows then pulls the bytes lazily with FILECONTENTS_SIZE/RANGE requests.
 * The run loop already owns xportLock while dispatching this callback, which
 * keeps the advertised path array stable until the response has been queued. */
static UINT cliprdr_client_file_contents_request(
        CliprdrServerContext *cliprdr,
        const CLIPRDR_FILE_CONTENTS_REQUEST *req) {
    RDPPeerContext *ctx = (RDPPeerContext *)cliprdr->custom;
    CLIPRDR_FILE_CONTENTS_RESPONSE resp = {0};
    uint8_t sizeBytes[8] = {0};
    uint8_t *rangeBytes = NULL;
    size_t responseLen = 0;
    int fd = -1;

    resp.common.msgType = CB_FILECONTENTS_RESPONSE;
    resp.common.msgFlags = CB_RESPONSE_FAIL;
    resp.streamId = req->streamId;
    if (req->dwFlags == FILECONTENTS_SIZE ||
        (req->dwFlags == FILECONTENTS_RANGE &&
         req->nPositionLow == 0 && req->nPositionHigh == 0)) {
        rdp_info("clipboard: file request stream=%u index=%u flags=0x%08x "
                 "offset=%u:%u requested=%u",
                 req->streamId, req->listIndex, req->dwFlags,
                 req->nPositionHigh, req->nPositionLow, req->cbRequested);
    }

    if (!ctx || !cliprdr->streamFileClipEnabled ||
        ctx->clipFormat != RDP_CLIPBOARD_FORMAT_FILE_GROUP_DESCRIPTOR_W ||
        !ctx->clipFilePaths || !ctx->clipFileSizes ||
        req->listIndex >= ctx->clipFileCount) {
        rdp_verbose("clipboard: rejecting file request stream=%u index=%u "
                    "(file clipboard unavailable)",
                    req->streamId, req->listIndex);
        goto send;
    }

    const char *path = ctx->clipFilePaths[req->listIndex];
    uint64_t advertisedSize = ctx->clipFileSizes[req->listIndex];

    if (req->dwFlags == FILECONTENTS_SIZE) {
        if (req->cbRequested != sizeof(sizeBytes)) {
            rdp_verbose("clipboard: invalid size request length=%u", req->cbRequested);
            goto send;
        }
        for (size_t i = 0; i < sizeof(sizeBytes); i++)
            sizeBytes[i] = (uint8_t)(advertisedSize >> (i * 8));
        resp.common.msgFlags = CB_RESPONSE_OK;
        resp.requestedData = sizeBytes;
        responseLen = sizeof(sizeBytes);
        goto send;
    }

    if (req->dwFlags != FILECONTENTS_RANGE) {
        rdp_verbose("clipboard: invalid file request flags=0x%08x", req->dwFlags);
        goto send;
    }

    uint64_t offset = ((uint64_t)req->nPositionHigh << 32) |
                      (uint64_t)req->nPositionLow;
    if (offset > advertisedSize) {
        rdp_verbose("clipboard: file request offset=%llu beyond size=%llu",
                    (unsigned long long)offset,
                    (unsigned long long)advertisedSize);
        goto send;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        rdp_verbose("clipboard: cannot open copied file '%s': %s",
                    path, strerror(errno));
        goto send;
    }
    struct stat st = {0};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (uint64_t)st.st_size != advertisedSize) {
        rdp_verbose("clipboard: copied file changed before paste: '%s'", path);
        goto send;
    }

    uint64_t remaining = advertisedSize - offset;
    size_t wanted = req->cbRequested;
    if (wanted > RDP_CLIPBOARD_FILE_MAX_CHUNK)
        wanted = RDP_CLIPBOARD_FILE_MAX_CHUNK;
    if ((uint64_t)wanted > remaining)
        wanted = (size_t)remaining;

    if (wanted > 0) {
        rangeBytes = malloc(wanted);
        if (!rangeBytes) goto send;
        while (responseLen < wanted) {
            ssize_t got = pread(fd, rangeBytes + responseLen,
                                wanted - responseLen,
                                (off_t)(offset + responseLen));
            if (got > 0) {
                responseLen += (size_t)got;
                continue;
            }
            if (got < 0 && errno == EINTR) continue;
            if (got < 0) {
                rdp_verbose("clipboard: read failed for '%s': %s",
                            path, strerror(errno));
                responseLen = 0;
                goto send;
            }
            break;
        }
    }

    resp.common.msgFlags = CB_RESPONSE_OK;
    resp.requestedData = rangeBytes;

send:
    if (fd >= 0) close(fd);
    resp.cbRequested = (UINT32)responseLen;
    resp.common.dataLen = 4u + resp.cbRequested;
    UINT rc = cliprdr->ServerFileContentsResponse(cliprdr, &resp);
    rdp_verbose("clipboard: -> FileContentsResponse stream=%u index=%u "
                "flags=0x%04x len=%zu rc=%u",
                req->streamId, req->listIndex, resp.common.msgFlags,
                responseLen, rc);
    free(rangeBytes);
    return rc;
}

/* ── Audio activated callback ──────────────────────────────────────────── */

/* Preferred client playback rate (Hz) from RDP_AUDIO_RATE, or 0 for "auto".
 *
 * mstsc commonly PLAYS rdpsnd at its 44100 device rate even when it advertises
 * 48000, so a 48000-tagged stream sounds a semitone low (44100/48000 = 0.919 —
 * exactly the reported drop). Preferring 44100 makes captured-rate == play-rate
 * and removes the shift. Gated behind an env var so the rate can be A/B tested
 * on hardware without a rebuild:
 *   "44100" (default) → prefer 44100 stereo 16-bit PCM
 *   "48000"           → prefer 48000
 *   "auto"            → no preference; take the first compatible client format */
static uint32_t rdp_preferred_audio_rate(void) {
    const char *env = getenv("RDP_AUDIO_RATE");
    if (!env || !*env)               return 44100;  /* default */
    if (strcmp(env, "auto") == 0)    return 0;
    long v = strtol(env, NULL, 10);
    if (v == 44100 || v == 48000 || v == 22050) return (uint32_t)v;
    rdp_info("RDP_AUDIO_RATE=\"%s\" not recognized — defaulting to 44100", env);
    return 44100;
}

static void rdpsnd_activated(RdpsndServerContext *rdpsnd) {
    RDPPeerContext *ctx = (RDPPeerContext *)rdpsnd->data;

    /* ── Diagnostics: dump the FULL negotiation so the real client offer is
     * visible in the log (the human reads this to confirm/choose the rate). */
    rdp_info("===== rdpsnd negotiation: %u client format(s) advertised =====",
             (unsigned)rdpsnd->num_client_formats);
    for (UINT16 i = 0; i < rdpsnd->num_client_formats; i++) {
        const AUDIO_FORMAT *cf = &rdpsnd->client_formats[i];
        rdp_info("  client[%u]: %u Hz, %u ch, %u-bit, tag 0x%04x, "
                 "blockAlign %u, avgBytes %u",
                 (unsigned)i, (unsigned)cf->nSamplesPerSec,
                 (unsigned)cf->nChannels, (unsigned)cf->wBitsPerSample,
                 (unsigned)cf->wFormatTag, (unsigned)cf->nBlockAlign,
                 (unsigned)cf->nAvgBytesPerSec);
    }
    rdp_info("----- server advertised %u format(s) -----",
             (unsigned)rdpsnd->num_server_formats);
    for (size_t j = 0; j < rdpsnd->num_server_formats; j++) {
        const AUDIO_FORMAT *sf = &rdpsnd->server_formats[j];
        rdp_info("  server[%zu]: %u Hz, %u ch, %u-bit, tag 0x%04x",
                 j, (unsigned)sf->nSamplesPerSec, (unsigned)sf->nChannels,
                 (unsigned)sf->wBitsPerSample, (unsigned)sf->wFormatTag);
    }

    /* CRITICAL (pitch bug): rdpsnd_server_send_samples() does NOT resample. It
     * encodes the bytes we hand it (described by ctx->rdpsnd->src_format) and
     * tags the WAVE PDU with wFormatNo = selected_client_format — an index into
     * the CLIENT's format list. The client plays our bytes at the SELECTED
     * CLIENT FORMAT's nSamplesPerSec. If that rate differs from the rate we
     * actually produced the PCM at, the client plays it faster/slower → pitch
     * shift.
     *
     * Guarantee src == play rate by (a) selecting a client format at the
     * PREFERRED rate (RDP_AUDIO_RATE, default 44100 — mstsc's usual device
     * rate), (b) pointing src_format at that EXACT client format BEFORE calling
     * SelectFormat (SelectFormat snapshots src_format to compute its
     * bytes-per-frame), and (c) resampling the 48 kHz tap to that negotiated
     * rate in AudioCapture (it polls rdp_peer_get_audio_rate).
     *
     * Two passes: first try to match the preferred rate; if the client offers
     * no compatible format at that rate, fall back to the first compatible
     * format of any rate so audio still works (just possibly shifted). */
    const uint32_t preferred = rdp_preferred_audio_rate();
    rdp_info("audio rate preference: %s (RDP_AUDIO_RATE)",
             preferred ? (preferred == 44100 ? "44100" :
                          preferred == 48000 ? "48000" : "22050") : "auto");

    int chosen = -1;
    /* Pass 1: preferred rate (skipped when preferred == 0 / "auto"). */
    if (preferred) {
        for (UINT16 i = 0; i < rdpsnd->num_client_formats && chosen < 0; i++) {
            if (rdpsnd->client_formats[i].nSamplesPerSec != preferred) continue;
            for (size_t j = 0; j < rdpsnd->num_server_formats; j++) {
                if (audio_format_compatible(&rdpsnd->server_formats[j],
                                            &rdpsnd->client_formats[i])) {
                    chosen = (int)i;
                    break;
                }
            }
        }
        if (chosen < 0)
            rdp_info("no compatible client format at preferred %u Hz — "
                     "falling back to first compatible format", preferred);
    }
    /* Pass 2: first compatible format of any rate. */
    for (UINT16 i = 0; i < rdpsnd->num_client_formats && chosen < 0; i++) {
        for (size_t j = 0; j < rdpsnd->num_server_formats; j++) {
            if (audio_format_compatible(&rdpsnd->server_formats[j],
                                        &rdpsnd->client_formats[i])) {
                chosen = (int)i;
                break;
            }
        }
    }

    if (chosen < 0) {
        rdp_error("no compatible audio format found among %u client formats",
                  (unsigned)rdpsnd->num_client_formats);
        return;
    }

    const AUDIO_FORMAT *sel = &rdpsnd->client_formats[chosen];
    /* Point src_format at the selected client format BEFORE SelectFormat —
     * SelectFormat reads src_format to compute src bytes-per-frame, and it is
     * the format SendSamples describes the PCM with, so it MUST equal the
     * client format we tag the wire with (same rate/ch/bits ⇒ no implicit
     * reinterpretation / pitch shift). */
    rdpsnd->src_format = (AUDIO_FORMAT *)sel;
    UINT rc = rdpsnd->SelectFormat(rdpsnd, (UINT16)chosen);
    if (rc != CHANNEL_RC_OK) {
        rdp_error("SelectFormat(idx %d) failed rc=%u — audio disabled",
                  chosen, (unsigned)rc);
        return;
    }

    /* Confirm SelectFormat actually committed the index we passed: the wire
     * wFormatNo and rdp_peer_get_audio_rate both read selected_client_format,
     * so a mismatch here would mean we resample to one rate but tag another. */
    UINT16 committed = rdpsnd->selected_client_format;
    if (committed != (UINT16)chosen) {
        rdp_error("selected_client_format mismatch: passed %d but context holds "
                  "%u — wire wFormatNo would disagree with resample rate!",
                  chosen, (unsigned)committed);
    }

    ctx->audioReady = true;
    rdp_info("audio format negotiated: client idx %d (committed %u) — "
             "%u Hz, %u ch, %u-bit, tag 0x%04x — wire wFormatNo=%u, "
             "tap will resample to %u Hz (src=play rate)",
             chosen, (unsigned)committed,
             (unsigned)sel->nSamplesPerSec, (unsigned)sel->nChannels,
             (unsigned)sel->wBitsPerSample, (unsigned)sel->wFormatTag,
             (unsigned)committed, (unsigned)sel->nSamplesPerSec);
}

/* Negotiated client playback sample rate (Hz), or 0 if audio is not yet
 * activated. AudioCapture polls this so its resampler targets the exact rate
 * the client plays at — see the pitch-bug note in rdpsnd_activated. */
uint32_t rdp_peer_get_audio_rate(freerdp_peer *peer) {
    if (!peer || !peer->context) return 0;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->rdpsnd || !ctx->audioReady) return 0;
    UINT16 idx = ctx->rdpsnd->selected_client_format;
    if (idx >= ctx->rdpsnd->num_client_formats) return 0;
    return (uint32_t)ctx->rdpsnd->client_formats[idx].nSamplesPerSec;
}

/* ── PostConnect: open virtual channels ───────────────────────────────── */

static BOOL peer_post_connect(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    rdp_verbose("post-connect: opening virtual channels");

    const BOOL networkAutoDetectEnabled = freerdp_settings_get_bool(
        peer->context->settings, FreeRDP_NetworkAutoDetect);
    rdpAutoDetect *autoDetect = autodetect_get(peer->context);
    rdp_info("RDP network characteristics: auto-detect=%d base-rtt=%u ms "
             "average-rtt=%u ms bandwidth=%u kbit/s state=%d",
             networkAutoDetectEnabled ? 1 : 0,
             autoDetect ? autoDetect->netCharBaseRTT : 0,
             autoDetect ? autoDetect->netCharAverageRTT : 0,
             autoDetect ? autoDetect->netCharBandwidth : 0,
             autoDetect ? (int)autoDetect->state : -1);

    const BOOL multitransportSupported = freerdp_settings_get_bool(
        peer->context->settings, FreeRDP_SupportMultitransport);
    const UINT32 multitransportFlags = freerdp_settings_get_uint32(
        peer->context->settings, FreeRDP_MultitransportFlags);
    rdp_info("RDP UDP negotiated capability: support=%d flags=0x%08x "
             "(FECR=%d preferred=%d soft-sync=%d)",
             multitransportSupported ? 1 : 0, multitransportFlags,
             (multitransportFlags & 0x00000001u) ? 1 : 0,
             (multitransportFlags & 0x00000100u) ? 1 : 0,
             (multitransportFlags & 0x00000200u) ? 1 : 0);

    /* GFX is a DYNAMIC virtual channel: it can only be opened once drdynvc has
     * reached DRDYNVC_STATE_READY, which does NOT happen until after PostConnect.
     * Opening here fails with "WTSVirtualChannelOpenEx failed" and the client
     * gets no video (black screen). Create the context now; defer Open() to the
     * run loop, which opens it when drdynvc is ready. */
    ctx->gfx = rdpgfx_server_context_new(ctx->vcm);
    if (!ctx->gfx) { rdp_error("rdpgfx_server_context_new failed"); return FALSE; }
    ctx->gfx->custom        = ctx;
    ctx->gfx->ChannelIdAssigned = gfx_channel_id_assigned;
    ctx->gfx->CapsAdvertise = gfx_caps_advertise;
    ctx->gfx->FrameAcknowledge = gfx_frame_acknowledge;
    ctx->gfx->QoeFrameAcknowledge = gfx_qoe_frame_acknowledge;
    ctx->surfaceId          = 1;
    /* External-thread mode: do NOT let GFX spawn its own thread. The default
     * (ownThread=TRUE) runs an internal loop calling rdpgfx_server_handle_messages
     * — which would race our run-loop's own handle_messages call and the encoder
     * thread's SurfaceCommand on the shared send_stream/zgfx state (heap
     * corruption / SIGABRT). With external mode WE are the sole driver, and a
     * mutex serializes the run loop vs the encoder. */
    if (ctx->gfx->Initialize)
        ctx->gfx->Initialize(ctx->gfx, TRUE);
    rdp_verbose("GFX context created (external-thread mode); open deferred");

    /* MS-RDPEDISP is another DVC and therefore also waits for drdynvc READY.
     * Its FreeRDP server context owns a small receive thread; the callback only
     * publishes the newest requested size atomically. The peer/session loop
     * performs all macOS and RDPGFX mutations in-order under xportLock. */
    ctx->disp = disp_server_context_new(ctx->vcm);
    if (ctx->disp) {
        ctx->disp->custom = ctx;
        ctx->disp->rdpcontext = peer->context;
        ctx->disp->MaxNumMonitors = 16;
        ctx->disp->MaxMonitorAreaFactorA = 8192;
        ctx->disp->MaxMonitorAreaFactorB = 8192;
        ctx->disp->DispMonitorLayout = disp_monitor_layout;
        rdp_verbose("Display Control context created; open deferred");
    } else {
        rdp_error("disp_server_context_new failed; dynamic resolution unavailable");
    }

    /* Clipboard. */
    ctx->cliprdr = cliprdr_server_context_new(ctx->vcm);
    if (ctx->cliprdr) {
        ctx->cliprdr->custom                   = ctx;
        ctx->cliprdr->rdpcontext               = peer->context;
        /* Register EVERY inbound callback BEFORE Open() so no client PDU is
         * dropped, and so the log shows the full MS-RDPECLIP exchange. */
        ctx->cliprdr->ClientCapabilities       = cliprdr_client_capabilities;
        ctx->cliprdr->ClientFormatList         = cliprdr_client_format_list;
        ctx->cliprdr->ClientFormatListResponse = cliprdr_client_format_list_response;
        ctx->cliprdr->ClientFormatDataResponse = cliprdr_client_format_data;
        ctx->cliprdr->ClientFormatDataRequest  = cliprdr_client_format_data_request;
        ctx->cliprdr->ClientFileContentsRequest = cliprdr_client_file_contents_request;
        ctx->cliprdr->ClientFileContentsResponse = cliprdr_client_file_contents_response;
        ctx->cliprdr->useLongFormatNames       = TRUE;
        ctx->cliprdr->streamFileClipEnabled    = TRUE;
        ctx->cliprdr->fileClipNoFilePaths      = TRUE;
        if (ctx->cliprdr->Open(ctx->cliprdr) != CHANNEL_RC_OK) {
            rdp_verbose("clipboard channel open failed");
            cliprdr_server_context_free(ctx->cliprdr);
            ctx->cliprdr = NULL;
        } else {
            /* We pump the channel via the shared VCM, NOT cliprdr's own Start()
             * thread — so the server-init handshake (Clipboard Capabilities +
             * Monitor Ready) is never sent automatically. Send it ourselves, or
             * the client never engages and copy/paste is dead BOTH directions. */
            CLIPRDR_GENERAL_CAPABILITY_SET general = {
                .capabilitySetType   = CB_CAPSTYPE_GENERAL,
                .capabilitySetLength = CB_CAPSTYPE_GENERAL_LEN,
                .version             = CB_CAPS_VERSION_2,
                .generalFlags        = CB_USE_LONG_FORMAT_NAMES |
                                       CB_STREAM_FILECLIP_ENABLED |
                                       CB_FILECLIP_NO_FILE_PATHS,
            };
            CLIPRDR_CAPABILITIES caps = {
                .common = { .msgType = CB_CLIP_CAPS, .msgFlags = 0,
                            .dataLen = 4 + CB_CAPSTYPE_GENERAL_LEN },
                .cCapabilitiesSets = 1,
                .capabilitySets = (CLIPRDR_CAPABILITY_SET *)&general,
            };
            CLIPRDR_MONITOR_READY ready = { .common = { .msgType = CB_MONITOR_READY } };
            UINT cc = ctx->cliprdr->ServerCapabilities(ctx->cliprdr, &caps);
            UINT mr = ctx->cliprdr->MonitorReady(ctx->cliprdr, &ready);
            rdp_verbose("clipboard channel opened (caps=%u monitor-ready=%u)", cc, mr);
        }
    }

    /* RDPDR drive-redirection static VC. Gated behind RDP_RDPDR_ENABLED=1. The
     * channel open is best-effort: if the client didn't advertise "rdpdr" in its
     * channel list, WTSVirtualChannelOpen returns NULL and we log + continue. */
    rdp_peer_open_rdpdr(peer);

    /* Audio. Advertise raw PCM stereo 16-bit at the standard rates mstsc
     * expects (48000 / 44100 / 22050). We DELIBERATELY offer only raw PCM, no
     * compressed codecs (AAC/ADPCM/GSM): our SendSamples feeds raw PCM, so a
     * negotiated codec would hand the client undecodable garbage.
     *
     * Why multiple rates (the pitch fix): rdpsnd_server_send_samples() does not
     * resample — the client plays our bytes at the SELECTED CLIENT FORMAT's
     * rate. mstsc frequently prefers 44100, so advertising only 48000 either
     * fails to match (silence) or, worse, ends up with the client replaying
     * 48000 bytes at 44100 → upward pitch shift. By offering the standard rates
     * we let a clean PCM format match; rdpsnd_activated then points src_format
     * at the selected client format and AudioCapture resamples the 48 kHz tap to
     * that exact rate (rdp_peer_get_audio_rate), so captured rate == play rate.
     *
     * rdpsnd_activated PREFERS the RDP_AUDIO_RATE rate (default 44100 — mstsc's
     * usual playback device rate) when the client offers it, falling back to the
     * first compatible format otherwise; list order here is no longer the
     * tie-breaker, but all three rates must be advertised so the preferred one
     * can match. Must be heap-allocated: rdpsnd_server_context_free() calls
     * free() on server_formats, so a static array would crash on teardown. */
    ctx->rdpsnd = rdpsnd_server_context_new(ctx->vcm);
    if (ctx->rdpsnd) {
        static const UINT32 kRates[] = { 48000, 44100, 22050 };
        const size_t nFmt = sizeof(kRates) / sizeof(kRates[0]);
        AUDIO_FORMAT *pcm = (AUDIO_FORMAT *)calloc(nFmt, sizeof(AUDIO_FORMAT));
        if (pcm) {
            for (size_t k = 0; k < nFmt; k++) {
                pcm[k].wFormatTag      = WAVE_FORMAT_PCM;
                pcm[k].nChannels       = 2;
                pcm[k].nSamplesPerSec  = kRates[k];
                pcm[k].nAvgBytesPerSec = kRates[k] * 2 * 2;
                pcm[k].nBlockAlign     = 2 * 2;
                pcm[k].wBitsPerSample  = 16;
            }
        }
        const char *audioLatencyEnv = getenv("RDP_AUDIO_LATENCY_MS");
        unsigned long audioLatency = audioLatencyEnv && *audioLatencyEnv
            ? strtoul(audioLatencyEnv, NULL, 10) : 100;
        if (audioLatency < 40 || audioLatency > 250) {
            rdp_info("RDP_AUDIO_LATENCY_MS=\"%s\" outside 40..250 — using 100 ms",
                     audioLatencyEnv ? audioLatencyEnv : "");
            audioLatency = 100;
        }

        ctx->rdpsnd->data               = ctx;
        ctx->rdpsnd->Activated          = rdpsnd_activated;
        ctx->rdpsnd->server_formats     = pcm;
        ctx->rdpsnd->num_server_formats = pcm ? nFmt : 0;
        /* FreeRDP groups PCM into packets of this duration. 50 ms was too
         * shallow when a large Progressive frame briefly occupied the shared
         * TLS transport; 100 ms gives Windows App enough jitter margin without
         * building the multi-second queue that caused the previous lag. */
        ctx->rdpsnd->latency             = (UINT32)audioLatency;
        /* Initial src_format; repointed to the selected client format on
         * activation. Must be non-NULL before SelectFormat (it bounds-checks
         * src_format). */
        ctx->rdpsnd->src_format         = pcm;
        if (ctx->rdpsnd->Initialize(ctx->rdpsnd, TRUE) != CHANNEL_RC_OK) {
            rdp_verbose("audio channel init failed");
            rdpsnd_server_context_free(ctx->rdpsnd);
            ctx->rdpsnd = NULL;
        } else {
            rdp_verbose("audio channel opened (PCM 48000/44100/22050, %lu ms packets)",
                        audioLatency);
        }
    }

    /* Audio input (MS-RDPEAI mic redirection). Gated behind RDP_AUDIO_INPUT=1.
     * Pass ctx->vcm so AudioInput.m never needs to touch the freerdp_peer struct. */
    ctx->audioInput = rdp_audio_input_open(ctx->vcm);
    if (ctx->audioInput)
        rdp_info("audio_input: channel open");

    return TRUE;
}

/* Client minimized / restored its RDP window. mstsc sends Suppress Output
 * (allow=FALSE) on minimize and again (allow=TRUE) on restore. While suppressed
 * we must STOP sending graphics; on restore we must resume AND send a fresh
 * keyframe — the client discarded everything while minimized, so a delta would
 * reference frames it no longer has (black until the next IDR). Without this the
 * window comes back black. */
static BOOL peer_suppress_output(rdpContext *context, BYTE allow,
                                 const RECTANGLE_16 *area) {
    (void)area;
    RDPPeerContext *ctx = (RDPPeerContext *)context;
    if (allow) {
        peer_restore_output(ctx, "Suppress Output allow", true);
    } else {
        if (!ctx->outputSuppressed) {
            ctx->outputSuppressedSinceMS = GetTickCount64();
            ctx->outputResumeProbeAttempted = false;
        }
        ctx->outputSuppressed = true;
        rdp_info("client output SUPPRESSED (background/minimized) — pausing "
                 "frames for at most %us", ctx->clientLivenessTimeoutMS / 1000u);
    }
    return TRUE;
}

static bool peer_publish_auto_reconnect_cookie(freerdp_peer *peer,
                                               RDPPeerContext *ctx) {
    if (!peer || !peer->context || !ctx) return false;
    rdpSettings *settings = peer->context->settings;

    const ARC_CS_PRIVATE_PACKET *incoming =
        (const ARC_CS_PRIVATE_PACKET *)freerdp_settings_get_pointer(
            settings, FreeRDP_ClientAutoReconnectCookie);
    if (incoming && incoming->cbLen == sizeof(*incoming) &&
        incoming->version == AUTO_RECONNECT_VERSION_1) {
        ctx->incomingReconnectCookie = *incoming;
        ctx->incomingReconnectCookieValid = true;
        rdp_info("MS-RDPBCGR auto-reconnect proof received (logonId=%u)",
                 incoming->logonId);
    }

    if (ctx->expectedReconnectCookieValid)
        return true; /* Core re-activation (for example resize), not reconnect. */
    if (!freerdp_settings_get_bool(settings,
                                   FreeRDP_AutoReconnectionPacketSupported)) {
        rdp_info("client did not negotiate standard auto-reconnect cookies");
        return false;
    }

    ARC_SC_PRIVATE_PACKET serverCookie = {
        .cbLen = sizeof(ARC_SC_PRIVATE_PACKET),
        .version = AUTO_RECONNECT_VERSION_1,
    };
    if (winpr_RAND(&serverCookie.logonId, sizeof(serverCookie.logonId)) < 0 ||
        winpr_RAND(serverCookie.arcRandomBits,
                   sizeof(serverCookie.arcRandomBits)) < 0) {
        rdp_error("auto-reconnect cookie random generation failed");
        return false;
    }

    BYTE zeroClientRandom[32] = {0};
    ARC_CS_PRIVATE_PACKET expected = {
        .cbLen = sizeof(ARC_CS_PRIVATE_PACKET),
        .version = AUTO_RECONNECT_VERSION_1,
        .logonId = serverCookie.logonId,
    };
    if (!winpr_HMAC(WINPR_MD_MD5, serverCookie.arcRandomBits,
                    sizeof(serverCookie.arcRandomBits), zeroClientRandom,
                    sizeof(zeroClientRandom), expected.securityVerifier,
                    sizeof(expected.securityVerifier))) {
        rdp_error("auto-reconnect security verifier generation failed");
        return false;
    }

    logon_info_ex info = {0};
    info.haveCookie = TRUE;
    info.LogonId = serverCookie.logonId;
    memcpy(info.ArcRandomBits, serverCookie.arcRandomBits,
           sizeof(info.ArcRandomBits));
    if (!peer->context->update->SaveSessionInfo(
            peer->context, INFO_TYPE_LOGON_EXTENDED_INF, &info)) {
        rdp_error("failed to send server auto-reconnect cookie");
        return false;
    }

    freerdp_settings_set_pointer_len(settings,
                                     FreeRDP_ServerAutoReconnectCookie,
                                     &serverCookie, 1);
    ctx->expectedReconnectCookie = expected;
    ctx->expectedReconnectCookieValid = true;
    rdp_info("standard auto-reconnect enabled (logonId=%u)",
             serverCookie.logonId);
    return true;
}

static BOOL peer_activate(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    ctx->activated = true;
    atomic_store_explicit(&ctx->lastClientResponseMS, GetTickCount64(),
                          memory_order_release);
    rdpSettings *s = peer->context->settings;
    UINT32 w = freerdp_settings_get_uint32(s, FreeRDP_DesktopWidth);
    UINT32 h = freerdp_settings_get_uint32(s, FreeRDP_DesktopHeight);
    UINT32 d = freerdp_settings_get_uint32(s, FreeRDP_ColorDepth);
    rdp_info("peer activated: %ux%u @%ubpp", w, h, d);
    rdp_info("pointer caps: colorCache=%u pointerCache=%u large=0x%08x",
             freerdp_settings_get_uint32(s, FreeRDP_ColorPointerCacheSize),
             freerdp_settings_get_uint32(s, FreeRDP_PointerCacheSize),
             freerdp_settings_get_uint32(s, FreeRDP_LargePointerFlag));

    /* Capture the logon credentials the client sent in the RDP info packet. NLA
     * is OFF (our OpenSSL build lacks md4/NTLM), so mstsc transmits them here in
     * the TLS-protected RDP logon. The session layer validates them against the
     * local macOS account (Authenticator) before granting/taking over a session.
     * NEVER log the password. Username/Domain are safe to log. */
    const char *user   = freerdp_settings_get_string(s, FreeRDP_Username);
    const char *domain = freerdp_settings_get_string(s, FreeRDP_Domain);
    rdp_info("logon credentials received: user=%s domain=%s (password %s)",
             user ? user : "(none)", domain ? domain : "(none)",
             freerdp_settings_get_string(s, FreeRDP_Password) ? "present" : "absent");

    (void)peer_publish_auto_reconnect_cookie(peer, ctx);

    if (ctx->callbacks.onReady)
        ctx->callbacks.onReady(ctx->callbacks.userdata, w, h, d);
    return TRUE;
}

bool rdp_peer_get_incoming_reconnect_cookie(freerdp_peer *peer,
                                            ARC_CS_PRIVATE_PACKET *cookie) {
    if (!peer || !peer->context || !cookie) return false;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->incomingReconnectCookieValid) return false;
    *cookie = ctx->incomingReconnectCookie;
    return true;
}

bool rdp_peer_get_expected_reconnect_cookie(freerdp_peer *peer,
                                            ARC_CS_PRIVATE_PACKET *cookie) {
    if (!peer || !peer->context || !cookie) return false;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->expectedReconnectCookieValid) return false;
    *cookie = ctx->expectedReconnectCookie;
    return true;
}

bool rdp_peer_disconnect_is_reconnectable(freerdp_peer *peer) {
    if (!peer || !peer->context) return false;
    UINT32 error = freerdp_get_last_error(peer->context);
    switch (error) {
        case FREERDP_ERROR_RPC_INITIATED_LOGOFF:
        case FREERDP_ERROR_LOGOFF_BY_USER:
        case FREERDP_ERROR_RPC_INITIATED_DISCONNECT_BY_USER:
            rdp_info("disconnect is intentional (%s); desktop will not be retained",
                     freerdp_get_last_error_name(error));
            return false;
        default:
            return true;
    }
}

/* Read the client's logon credentials from the negotiated peer settings. Valid
 * after peer_activate has run (Activate / onReady). The returned pointers are
 * owned by FreeRDP settings and live as long as the peer; any may be NULL when
 * the client supplied no value. NEVER log *password. */
void rdp_peer_get_credentials(freerdp_peer *peer,
                              const char **username,
                              const char **password,
                              const char **domain) {
    const char *u = NULL, *p = NULL, *dm = NULL;
    if (peer && peer->context) {
        rdpSettings *s = peer->context->settings;
        u  = freerdp_settings_get_string(s, FreeRDP_Username);
        p  = freerdp_settings_get_string(s, FreeRDP_Password);
        dm = freerdp_settings_get_string(s, FreeRDP_Domain);
    }
    if (username) *username = u;
    if (password) *password = p;
    if (domain)   *domain   = dm;
}

/* ── Public API ────────────────────────────────────────────────────────── */

/* Register FreeRDP's built-in server WTS implementation exactly once, before
 * the first WTSOpenServerA. Without this, WinPR's WTS layer tries to dlopen the
 * external FreeRDS plugin (libfreerds-fdsapi.so, Linux-only, absent on macOS),
 * WTSOpenServerA returns NULL, and every connection dies in context_new with
 * "ContextNew callback failed". The sample server does the same (sfreerdp.c).
 *
 * FreeRDP_InitWtsApi is exported by libfreerdp-server but only declared in an
 * internal header the public SDK does not ship, so we forward-declare it. The
 * signature matches WinPR's INIT_WTSAPI_FN typedef. */
extern const WtsApiFunctionTable *FreeRDP_InitWtsApi(void);

static pthread_once_t g_wts_once = PTHREAD_ONCE_INIT;
static void register_freerdp_wts(void) {
    WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi());
}

freerdp_peer *rdp_peer_create(int fd, const RDPPeerCallbacks *callbacks) {
    winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);
    pthread_once(&g_wts_once, register_freerdp_wts);
    rdp_verbose("creating peer for fd=%d", fd);

    freerdp_peer *peer = freerdp_peer_new(fd);
    if (!peer) { rdp_error("freerdp_peer_new failed"); return NULL; }

    /* ContextSize (PascalCase in 3.x) replaces context_size. */
    peer->ContextSize  = sizeof(RDPPeerContext);
    peer->ContextNew   = context_new;
    peer->ContextFree  = context_free;

    if (!freerdp_peer_context_new(peer)) {
        rdp_error("freerdp_peer_context_new failed");
        freerdp_peer_free(peer);
        return NULL;
    }

    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (callbacks) ctx->callbacks = *callbacks;

#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
    if (!freerdp_peer_set_multitransport_bootstrap_handler(
            peer, peer_multitransport_bootstrap, ctx)) {
        rdp_error("failed to install private FreeRDP UDP bootstrap handler");
        freerdp_peer_context_free(peer);
        freerdp_peer_free(peer);
        return NULL;
    }
#endif

    peer_apply_settings(peer);
    peer->PostConnect = peer_post_connect;
    peer->Activate    = peer_activate;
    /* Handle minimize/restore (Suppress Output) so the window doesn't come back
     * black. SuppressOutput lives on rdpUpdate in 3.x. */
    peer->context->update->RefreshRect = peer_refresh_rect;
    peer->context->update->SuppressOutput = peer_suppress_output;

    /* Input is on rdpContext, not on freerdp_peer in 3.x. */
    peer->context->input->SynchronizeEvent     = peer_synchronize;
    peer->context->input->KeyboardEvent        = peer_keyboard;
    peer->context->input->UnicodeKeyboardEvent = peer_unicode_keyboard;
    peer->context->input->MouseEvent           = peer_mouse;
    peer->context->input->ExtendedMouseEvent   = peer_mouse_ex;
    peer->context->input->FocusInEvent         = peer_focus_in;
    peer->context->input->KeyboardPauseEvent   = peer_keyboard_pause;
    peer->context->input->RelMouseEvent        = peer_rel_mouse;
    peer->context->input->QoEEvent             = peer_qoe;

    if (!peer->Initialize(peer)) {
        rdp_error("peer Initialize failed (TLS handshake error)");
        freerdp_peer_context_free(peer);
        freerdp_peer_free(peer);
        return NULL;
    }

    rdp_verbose("peer initialized");
    return peer;
}

void rdp_peer_destroy(freerdp_peer *peer) {
    if (!peer) return;
    rdp_verbose("destroying peer");
    freerdp_peer_context_free(peer);
    freerdp_peer_free(peer);
}

bool rdp_peer_close_gracefully(freerdp_peer *peer, uint32_t errorInfo) {
    if (!peer || !peer->context) return false;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;

    /* Close emits protocol PDUs on the same TLS transport used by video,
     * audio, and virtual channels. The session stops those producers before
     * entering here; retain the transport lock so no late callback can
     * interleave bytes with the disconnect sequence. */
    pthread_mutex_lock(&ctx->xportLock);
    bool sent = false;
    if (ctx->activated && peer->Close) {
        freerdp_set_error_info(peer->context->rdp, errorInfo);
        sent = peer->Close(peer) ? true : false;
    }
    pthread_mutex_unlock(&ctx->xportLock);

    if (sent)
        rdp_info("sent graceful RDP disconnect (errorInfo=0x%08x)", errorInfo);
    else
        rdp_info("graceful RDP disconnect unavailable; transport close will be used");
    return sent;
}

/*
 * Event-driven run: waits on peer transport handles + VCM channel event
 * rather than spinning. Blocks up to 50ms then returns — caller checks
 * disconnect flag. This replaces the busy-poll loop with proper WaitForMultiple.
 */
bool rdp_peer_run_once(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;

    HANDLE events[70] = {0};   /* transport(64) + vcm + gfx + clip + rdpdr + ai_input + spare */
    DWORD  nCount = 0;

    /* Peer transport events (typically 1-2 handles). */
    DWORD n = peer->GetEventHandles(peer, events, 64);
    if (n == 0) { rdp_error("GetEventHandles returned 0"); return false; }
    nCount += n;

    /* VCM channel event (drdynvc, cliprdr, etc.). */
    HANDLE vcmEvent = WTSVirtualChannelManagerGetEventHandle(ctx->vcm);
    if (vcmEvent) events[nCount++] = vcmEvent;

    /* GFX channel event (only once the DVC is actually open). */
    if (ctx->gfx && ctx->gfxOpened) {
        HANDLE gfxEvent = rdpgfx_server_get_event_handle(ctx->gfx);
        if (gfxEvent) events[nCount++] = gfxEvent;
    }

    /* Clipboard channel event. cliprdr is a STATIC virtual channel opened in
     * PostConnect, so its event handle is valid as soon as Open() succeeded —
     * no drdynvc dependency (unlike GFX). We pump it here via the shared run
     * loop instead of cliprdr's own Start() reader thread (which would race the
     * transport against this loop and the encoder thread). WITHOUT this wait +
     * the drain below, cliprdr_server_read is NEVER called, so the client's
     * ClientCapabilities / ClientFormatList / FormatDataRequest /
     * FormatDataResponse PDUs are never read off the wire — copy/paste is dead
     * BOTH directions even though our outbound caps/monitor-ready/format-list
     * were sent fine. THIS was the bug. */
    if (ctx->cliprdr) {
        HANDLE clipEvent = ctx->cliprdr->GetEventHandle(ctx->cliprdr);
        if (clipEvent) events[nCount++] = clipEvent;
    }

    /* RDPDR static VC event (only when RDP_RDPDR_ENABLED=1 and channel open). */
    if (ctx->rdpdrEvent) events[nCount++] = ctx->rdpdrEvent;

    /* AUDIO_INPUT channel event (only when RDP_AUDIO_INPUT=1 and channel open). */
    HANDLE aiEvent = rdp_audio_input_event(ctx->audioInput);
    if (aiEvent) events[nCount++] = aiEvent;

    DWORD status = WaitForMultipleObjects(nCount, events, FALSE, 50 /*ms*/);
    if (status == WAIT_FAILED) {
        rdp_error("WaitForMultipleObjects failed");
        return false;
    }

    /* BetterDisplay mode changes and ScreenCaptureKit restart can take hundreds
     * of milliseconds. Perform that portion without the transport mutex; the
     * helper reacquires xportLock only for the short ordered GFX reset/create
     * sequence, preventing a resize/capture callback deadlock. */
    if (atomic_load_explicit(&ctx->pendingDisplaySize,
                             memory_order_acquire) != 0 &&
        !peer_apply_pending_display_resize(peer, ctx))
        return false;

    /* Everything below WRITES to the transport (CheckFileDescriptor sends acks +
     * input responses, the VCM pump flushes channel PDUs incl. cliprdr, GFX
     * handle_messages drains/answers). Hold xportLock across the whole section so
     * none of it interleaves with the encoder thread's SurfaceCommand, the audio
     * thread's SendSamples, or the clipboard thread's ServerFormatList. The 50ms
     * Wait above is deliberately OUTSIDE the lock so we don't starve those threads
     * while idle. */
    bool ok = true;
    pthread_mutex_lock(&ctx->xportLock);

    /* FreeRDP's non-blocking TLS transport can retain encrypted output in its
     * buffered BIO after a short/blocked socket write. CheckFileDescriptor is a
     * receive pump; it does not flush that output buffer. Drain it whenever the
     * transport event (or our 50 ms safety timeout) wakes this loop, otherwise a
     * transiently full local FRP socket can leave graphics queued indefinitely.
     * All transport access stays under xportLock. */
    if (peer->IsWriteBlocked && peer->IsWriteBlocked(peer)) {
        atomic_store_explicit(&ctx->transportWriteBlocked, true,
                              memory_order_release);
        atomic_fetch_add_explicit(&ctx->transportDrainAttempts, 1,
                                  memory_order_relaxed);
        int drainRc = peer->DrainOutputBuffer
            ? peer->DrainOutputBuffer(peer) : 1;
        if (drainRc < 0) {
            atomic_fetch_add_explicit(&ctx->transportDrainErrors, 1,
                                      memory_order_relaxed);
            rdp_error("FreeRDP transport output drain failed");
            ok = false;
        } else if (drainRc > 0) {
            atomic_fetch_add_explicit(&ctx->transportDrainStillBlocked, 1,
                                      memory_order_relaxed);
        } else {
            atomic_store_explicit(&ctx->transportWriteBlocked, false,
                                  memory_order_release);
        }
    } else {
        atomic_store_explicit(&ctx->transportWriteBlocked, false,
                              memory_order_release);
    }

    /* Process peer transport data. */
    if (ok && !peer->CheckFileDescriptor(peer)) {
        rdp_verbose("peer transport closed");
        ok = false;
    }

    /* Dispatch any pending virtual channel messages. This also advances the
     * drdynvc state machine toward READY. */
    if (ok && vcmEvent && WaitForSingleObject(vcmEvent, 0) == WAIT_OBJECT_0) {
        if (!WTSVirtualChannelManagerCheckFileDescriptor(ctx->vcm)) {
            rdp_error("VCM check failed");
            ok = false;
        }
    }

    /* Open the GFX dynamic virtual channel once drdynvc is READY. GFX cannot be
     * opened in PostConnect (drdynvc isn't up yet) — doing it here is how the
     * shadow server brings up DVCs. Without this the client gets no video. */
    if (ok && ctx->gfx && !ctx->gfxOpened &&
        WTSVirtualChannelManagerGetDrdynvcState(ctx->vcm) == DRDYNVC_STATE_READY) {
        if (ctx->gfx->Open(ctx->gfx)) {
            ctx->gfxOpened = true;
            rdp_info("GFX channel opened (drdynvc ready)");
        } else {
            rdp_error("GFX Open failed despite drdynvc ready");
        }
    }

    if (ok && ctx->disp && !ctx->dispOpened &&
        WTSVirtualChannelManagerGetDrdynvcState(ctx->vcm) == DRDYNVC_STATE_READY) {
        UINT drc = ctx->disp->Open(ctx->disp);
        if (drc == CHANNEL_RC_OK) {
            ctx->dispOpened = true;
            drc = ctx->disp->DisplayControlCaps(ctx->disp);
            if (drc == CHANNEL_RC_OK)
                rdp_info("MS-RDPEDISP channel opened; dynamic resolution ready");
            else {
                rdp_error("MS-RDPEDISP capability send failed: %u", drc);
                ok = false;
            }
        } else {
            rdp_error("MS-RDPEDISP Open failed despite drdynvc ready: %u", drc);
        }
    }

    /* Drain GFX channel messages once the channel is open. */
    if (ok && ctx->gfx && ctx->gfxOpened) {
        HANDLE gfxEvent = rdpgfx_server_get_event_handle(ctx->gfx);
        if (gfxEvent && WaitForSingleObject(gfxEvent, 0) == WAIT_OBJECT_0) {
            rdpgfx_server_handle_messages(ctx->gfx);
        }
    }

    if (ok && !peer_apply_pending_graphics_resync_locked(ctx))
        ok = false;

#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
    /* The RDPEMT tunnel is authenticated independently on the UDP listener.
     * Only after GFX has exchanged caps do we flush its existing TCP PDUs and
     * ask the client to move this one DVC to the reliable UDP tunnel. */
    if (ok && !ctx->udpSoftSyncRequested && ctx->gfxReady && ctx->gfxChannelId &&
        atomic_load_explicit(&ctx->udpTunnelReady, memory_order_acquire)) {
        const UINT32 channelId = ctx->gfxChannelId;
        if (WTSVirtualChannelManagerStartSoftSync(ctx->vcm, TUNNELTYPE_UDPFECR,
                                                  &channelId, 1)) {
            ctx->udpSoftSyncRequested = true;
            rdp_info("Soft-Sync requested: GFX DVC %u -> reliable UDP", channelId);
        } else {
            rdp_error("Soft-Sync request could not be queued for GFX DVC %u",
                      channelId);
        }
    }
    if (ok && ctx->udpSoftSyncRequested && !ctx->udpSoftSyncActive &&
        WTSVirtualChannelManagerIsSoftSyncActive(ctx->vcm)) {
        ctx->udpSoftSyncActive = true;
        rdp_info("Soft-Sync active: GFX traffic is now using reliable UDP");
        ctx->sentKeyframe = false;
        if (ctx->callbacks.onKeyframeRequest)
            ctx->callbacks.onKeyframeRequest(ctx->callbacks.userdata);
    }
#endif

    /* Drain clipboard channel messages. CheckEventHandle == cliprdr_server_read:
     * it reads one PDU off the static channel and dispatches it to our Client*
     * callbacks, which themselves write responses (FormatListResponse,
     * FormatDataRequest/Response) back over the transport — hence it MUST run
     * under xportLock, which we already hold here. This is what finally lets us
     * SEE the client engage the clipboard. */
    if (ok && ctx->cliprdr) {
        HANDLE clipEvent = ctx->cliprdr->GetEventHandle(ctx->cliprdr);
        if (clipEvent && WaitForSingleObject(clipEvent, 0) == WAIT_OBJECT_0) {
            UINT crc = ctx->cliprdr->CheckEventHandle(ctx->cliprdr);
            if (crc != CHANNEL_RC_OK)
                rdp_verbose("clipboard read failed: %u", crc);
        }
    }

    /* Drain rdpdr static VC messages (RDP_RDPDR_ENABLED=1 only). */
    if (ok && ctx->rdpdrEvent &&
        WaitForSingleObject(ctx->rdpdrEvent, 0) == WAIT_OBJECT_0) {
        rdp_peer_pump_rdpdr(peer);
    }

    /* Drain AUDIO_INPUT DATA PDUs and play on Mac speaker (RDP_AUDIO_INPUT=1).
     * rdp_audio_input_pump is a read-only drain — no transport writes — so it
     * does not strictly need xportLock, but we hold it here anyway for a
     * consistent single-threaded pump discipline (mirrors rdpdr). */
    if (ok && ctx->audioInput) {
        if (!aiEvent || WaitForSingleObject(aiEvent, 0) == WAIT_OBJECT_0) {
            rdp_audio_input_pump(ctx->audioInput);
        }
    }

    /* iPadOS can suspend Windows App without closing TCP and without sending a
     * Suppress Output PDU. FRP therefore keeps a socket that looks connected,
     * while the client has stopped decoding and acknowledging graphics. A
     * static healthy desktop still answers the two-second heartbeat frame, so
     * expire only a previously responsive client with outstanding frames. The
     * session layer treats this like a network interruption and retains the
     * BetterDisplay desktop for standard auto-reconnect. */
    if (ok) {
        const uint64_t nowMS = GetTickCount64();
        const uint32_t ackFrame = atomic_load_explicit(
            &ctx->lastAckFrameId, memory_order_acquire);
        const uint32_t qoeFrame = atomic_load_explicit(
            &ctx->lastQoeFrameId, memory_order_acquire);
        const uint64_t qoeAcks = atomic_load_explicit(
            &ctx->qoeAckCount, memory_order_acquire);
        const uint64_t lastResponseMS = atomic_load_explicit(
            &ctx->lastClientResponseMS, memory_order_acquire);
        const RDPClientLivenessSnapshot liveness = {
            .activated = ctx->activated,
            .gfxReady = ctx->gfxReady,
            .outputSuppressed = ctx->outputSuppressed,
            .feedbackSeen = atomic_load_explicit(
                                &ctx->gfxAckSeen, memory_order_acquire) ||
                            qoeAcks > 0u,
            .sentFrameId = ctx->frameId,
            .ackFrameId = ackFrame,
            .qoeFrameId = qoeFrame,
            .lastResponseMS = lastResponseMS,
            .suppressedSinceMS = ctx->outputSuppressedSinceMS,
        };
        if (!ctx->outputResumeProbeAttempted &&
            rdp_client_liveness_suppressed_probe_due(
                &liveness, nowMS, RDP_BACKGROUND_RESUME_PROBE_MS)) {
            rdp_info("client omitted foreground restore signal for %ums; "
                     "sending one compatibility full-refresh probe",
                     RDP_BACKGROUND_RESUME_PROBE_MS);
            peer_restore_output(ctx, "server compatibility probe", false);
        }
        if (rdp_client_liveness_timed_out(
                &liveness, nowMS, ctx->clientLivenessTimeoutMS)) {
            if (liveness.outputSuppressed) {
                const uint64_t ageMS = nowMS - liveness.suppressedSinceMS;
                rdp_info("client output remained suppressed for %llums; "
                         "closing stale transport for auto-reconnect",
                         (unsigned long long)ageMS);
            } else {
                const uint64_t ageMS = nowMS - lastResponseMS;
                rdp_info("client graphics liveness timeout after %llums "
                         "(sent=%u ack=%u qoe=%u); closing stale transport for "
                         "auto-reconnect",
                         (unsigned long long)ageMS,
                         ctx->frameId, ackFrame, qoeFrame);
            }
            ok = false;
        }
    }

    pthread_mutex_unlock(&ctx->xportLock);
    return ok;
}

void rdp_peer_set_udp_tunnel_ready(freerdp_peer *peer, bool ready) {
    if (!peer || !peer->context) return;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    atomic_store_explicit(&ctx->udpTunnelReady, ready, memory_order_release);
    if (!ready)
        atomic_store_explicit(&ctx->udpStatsObservedAtMS, 0u,
                              memory_order_release);
}

void rdp_peer_update_udp_transport_metrics(
    freerdp_peer *peer, const RDPPeerUDPTransportMetrics *metrics) {
    if (!peer || !peer->context || !metrics || !metrics->observedAtMS)
        return;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    const uint64_t priorRetransmissions = atomic_exchange_explicit(
        &ctx->udpRetransmissions, metrics->retransmissions,
        memory_order_relaxed);
    const uint64_t priorLossEvents = atomic_exchange_explicit(
        &ctx->udpLossEvents, metrics->lossEvents, memory_order_relaxed);
    if (metrics->retransmissions > priorRetransmissions ||
        metrics->lossEvents > priorLossEvents) {
        atomic_store_explicit(&ctx->udpLastCongestionMS,
                              metrics->observedAtMS,
                              memory_order_release);
    }
    atomic_store_explicit(&ctx->udpSmoothedRTTMS, metrics->smoothedRTTMS,
                          memory_order_relaxed);
    atomic_store_explicit(&ctx->udpInflightPackets, metrics->inflightPackets,
                          memory_order_relaxed);
    atomic_store_explicit(&ctx->udpCongestionWindowPackets,
                          metrics->congestionWindowPackets,
                          memory_order_relaxed);
    atomic_store_explicit(&ctx->udpQueuedBytes, metrics->queuedBytes,
                          memory_order_relaxed);
    /* Publish the timestamp last so a QoE callback never observes a new sample
     * time with fields from the previous RDPUDP2 snapshot. */
    atomic_store_explicit(&ctx->udpStatsObservedAtMS,
                          metrics->observedAtMS, memory_order_release);
}

bool rdp_peer_is_udp_soft_sync_active(freerdp_peer *peer) {
#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
    if (!peer || !peer->context) return false;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    pthread_mutex_lock(&ctx->xportLock);
    const bool active = ctx->udpSoftSyncActive ||
                        WTSVirtualChannelManagerIsSoftSyncActive(ctx->vcm);
    pthread_mutex_unlock(&ctx->xportLock);
    return active;
#else
    (void)peer;
    return false;
#endif
}

bool rdp_peer_receive_udp_dvc(freerdp_peer *peer,
                              const uint8_t *data, size_t len) {
#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
    if (!peer || !peer->context || !data || !len || len > UINT32_MAX)
        return false;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    pthread_mutex_lock(&ctx->xportLock);
    if (!ctx->udpSoftSyncActive &&
        WTSVirtualChannelManagerIsSoftSyncActive(ctx->vcm))
        ctx->udpSoftSyncActive = true;
    BOOL ok = ctx->udpSoftSyncActive &&
              WTSVirtualChannelManagerReceiveDVCTunnelData(
                  ctx->vcm, data, (UINT32)len);
    pthread_mutex_unlock(&ctx->xportLock);
    return ok ? true : false;
#else
    (void)peer; (void)data; (void)len;
    return false;
#endif
}

bool rdp_peer_send_h264_frame(freerdp_peer *peer,
                               const uint8_t *data, size_t len,
                               uint32_t width, uint32_t height,
                               bool isKeyFrame,
                               uint16_t dirtyX, uint16_t dirtyY,
                               uint16_t dirtyW, uint16_t dirtyH) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->gfxReady || !ctx->gfx) { rdp_debug("gfx not ready"); return false; }
    if (ctx->graphicsMode != RDPGraphicsModeAVC420) return false;

    /* Client minimized: it ignores (and may choke on) graphics while output is
     * suppressed. Drop frames until it restores (which forces a fresh keyframe). */
    if (ctx->outputSuppressed) return true;

    /* The first frame the client receives MUST be a self-contained keyframe.
     * Frames encoded while the GFX channel was still opening were discarded, so a
     * delta sent now references frames the client never got -> undecodable (black).
     * Drop deltas until a keyframe goes out, asking the encoder to emit one. */
    if (!ctx->sentKeyframe && !isKeyFrame) {
        if (!ctx->keyframeRequested && ctx->callbacks.onKeyframeRequest) {
            ctx->keyframeRequested = true;
            ctx->callbacks.onKeyframeRequest(ctx->callbacks.userdata);
            rdp_debug("delta before first keyframe — requested IDR, dropping");
        }
        return true;
    }
    if (isKeyFrame) { ctx->sentKeyframe = true; ctx->keyframeRequested = false; }

    /* Build the damage region. Keyframes refresh the whole surface, so they
     * must claim the full extent; inter-frames claim only the dirty rect.
     * Align to 16px macroblock boundaries and clamp to surface bounds — the
     * AVC420 region must lie within the decoded picture or the client rejects it. */
    RECTANGLE_16 rect;
    if (isKeyFrame || dirtyW == 0 || dirtyH == 0) {
        rect.left = 0; rect.top = 0;
        rect.right = (UINT16)width; rect.bottom = (UINT16)height;
    } else {
        uint32_t left   = dirtyX & ~15u;                 /* round down to 16 */
        uint32_t top    = dirtyY & ~15u;
        uint32_t right  = (dirtyX + dirtyW + 15u) & ~15u; /* round up to 16 */
        uint32_t bottom = (dirtyY + dirtyH + 15u) & ~15u;
        if (right  > width)  right  = width;
        if (bottom > height) bottom = height;
        if (left   >= right)  { left = 0; right = (uint32_t)width; }
        if (top    >= bottom) { top = 0;  bottom = (uint32_t)height; }
        rect.left = (UINT16)left;  rect.top = (UINT16)top;
        rect.right = (UINT16)right; rect.bottom = (UINT16)bottom;
    }

    /* quantQualityVals MUST be a valid parallel array — the server serializer
     * dereferences quantQualityVals[i] for every region rect. NULL crashes.
     * qp is a quality hint (QoE only, not decode-critical); qualityVal mirrors
     * FreeRDP's own encoder: 100 - (qp & 0x3F). */
    RDPGFX_H264_QUANT_QUALITY quant = {0};
    quant.qp         = 26;
    quant.qualityVal = (BYTE)(100 - (26 & 0x3F));

    RDPGFX_AVC420_BITMAP_STREAM avc = {0};
    avc.data                  = (BYTE *)data;
    avc.length                = (UINT32)len;
    avc.meta.numRegionRects   = 1;
    avc.meta.regionRects      = &rect;
    avc.meta.quantQualityVals = &quant;

    /* The H.264 picture is full-surface, so the destination extent is too. */
    RDPGFX_SURFACE_COMMAND cmd = {0};
    cmd.surfaceId = ctx->surfaceId;
    cmd.codecId   = RDPGFX_CODECID_AVC420;
    /* cmd.format is a FreeRDP COLOR format (color.h), not a GFX wire enum.
     * rdpgfx_write_surface_command only accepts BGRX32/BGRA32 (-> XRGB/ARGB
     * on the wire). Using the wire enum yields "Format UNKNOWN not supported". */
    cmd.format    = PIXEL_FORMAT_BGRX32;
    cmd.right     = (UINT16)width;
    cmd.bottom    = (UINT16)height;
    cmd.length    = (UINT32)len;
    cmd.data      = (BYTE *)data;
    cmd.extra     = &avc;

    /* Wrap the surface command in StartFrame/EndFrame markers, like the shadow
     * server. mstsc needs the frame boundaries (and frameId) to composite the
     * decoded surface to the display — bare SurfaceCommands often don't render. */
    uint32_t fid = ++ctx->frameId;
    RDPGFX_START_FRAME_PDU startFrame = {0};
    startFrame.frameId = fid;
    RDPGFX_END_FRAME_PDU endFrame = {0};
    endFrame.frameId = fid;

    /* Video is disposable and ScreenCapture retains the newest frame. Do not
     * wait behind an active writer, but also do not give a continuously queued
     * audio sender absolute priority: that policy reduced video to ~2 fps. */
    if (pthread_mutex_trylock(&ctx->xportLock) != 0)
        return true;
    UINT rc = ctx->gfx->SurfaceFrameCommand(ctx->gfx, &cmd, &startFrame, &endFrame);
    pthread_mutex_unlock(&ctx->xportLock);
    if (rc != CHANNEL_RC_OK) { rdp_error("SurfaceFrameCommand failed: %u", rc); return false; }
    rdp_debug("sent %s frame: region=(%u,%u)-(%u,%u) len=%zu",
              isKeyFrame ? "key" : "delta",
              rect.left, rect.top, rect.right, rect.bottom, len);
    return true;
}

RDPGraphicsMode rdp_peer_graphics_mode(freerdp_peer *peer) {
    if (!peer || !peer->context) return RDPGraphicsModeUnknown;
    return ((RDPPeerContext *)peer->context)->graphicsMode;
}

static bool progressive_region_add_rect(REGION16 *region,
                                        const RECTANGLE_16 *source,
                                        uint32_t width, uint32_t height) {
    if (!region || !source) return false;
    uint32_t left = source->left;
    uint32_t top = source->top;
    uint32_t right = source->right;
    uint32_t bottom = source->bottom;
    if (right > width) right = width;
    if (bottom > height) bottom = height;
    if (left >= right || top >= bottom) return true;
    RECTANGLE_16 clipped = {
        .left = (UINT16)left, .top = (UINT16)top,
        .right = (UINT16)right, .bottom = (UINT16)bottom,
    };
    return region16_union_rect(region, region, &clipped) ? true : false;
}

static bool progressive_region_union(REGION16 *dst, const REGION16 *src,
                                     uint32_t width, uint32_t height) {
    if (!dst || !src || region16_is_empty(src)) return true;
    UINT32 count = 0;
    const RECTANGLE_16 *rects = region16_rects(src, &count);
    for (UINT32 i = 0; i < count; i++) {
        if (!progressive_region_add_rect(dst, &rects[i], width, height))
            return false;
    }
    return true;
}

/* Delivery is serial, so the pending REGION16 can be updated without another
 * mutex. Region16 canonicalizes overlaps; cap pathological fragmentation at 256
 * rectangles by collapsing to extents rather than allowing unbounded growth. */
static void progressive_accumulate_region(RDPPeerContext *ctx,
                                          const REGION16 *damage,
                                          uint32_t width, uint32_t height) {
    if (!ctx || !damage || !ctx->progressivePendingRegionInitialized) return;
    if (!progressive_region_union(&ctx->progressivePendingRegion, damage,
                                  width, height)) {
        rdp_error("failed to accumulate Progressive damage region");
        return;
    }
    if (region16_n_rects(&ctx->progressivePendingRegion) > 256) {
        RECTANGLE_16 extents = *region16_extents(&ctx->progressivePendingRegion);
        region16_clear(&ctx->progressivePendingRegion);
        region16_union_rect(&ctx->progressivePendingRegion,
                            &ctx->progressivePendingRegion, &extents);
    }
}

static uint64_t progressive_region_pixels(const REGION16 *region) {
    if (!region) return 0;
    UINT32 count = 0;
    const RECTANGLE_16 *rects = region16_rects(region, &count);
    uint64_t pixels = 0;
    for (UINT32 i = 0; i < count; i++) {
        pixels += (uint64_t)(rects[i].right - rects[i].left) *
                  (uint64_t)(rects[i].bottom - rects[i].top);
    }
    return pixels;
}

/* Convert a tile bitmap into horizontal runs. REGION16 then merges vertically
 * adjacent equal runs, so a full-screen change becomes one rectangle instead
 * of hundreds of 64x64 entries. This preserves exact changed tiles without the
 * bandwidth inflation of collapsing irregular damage to its bounding box. */
static bool progressive_region_from_tile_mask(RDPPeerContext *ctx,
                                              const uint8_t *mask,
                                              uint32_t width, uint32_t height,
                                              REGION16 *region,
                                              uint32_t *markedTiles) {
    if (markedTiles) *markedTiles = 0;
    if (!ctx || !mask || !region) return false;
    for (uint32_t ty = 0; ty < ctx->progressiveTileRows; ty++) {
        uint32_t tx = 0;
        while (tx < ctx->progressiveTileColumns) {
            size_t index = (size_t)ty * ctx->progressiveTileColumns + tx;
            if (!mask[index]) { tx++; continue; }
            uint32_t start = tx;
            while (tx < ctx->progressiveTileColumns &&
                   mask[(size_t)ty * ctx->progressiveTileColumns + tx]) {
                if (markedTiles) (*markedTiles)++;
                tx++;
            }
            uint32_t left = start * 64u;
            uint32_t right = tx * 64u;
            uint32_t top = ty * 64u;
            uint32_t bottom = top + 64u;
            if (right > width) right = width;
            if (bottom > height) bottom = height;
            RECTANGLE_16 run = {
                .left = (UINT16)left, .top = (UINT16)top,
                .right = (UINT16)right, .bottom = (UINT16)bottom,
            };
            if (!region16_union_rect(region, region, &run)) return false;
        }
    }
    return true;
}

static void progressive_set_quality_tiles(RDPPeerContext *ctx,
                                          const REGION16 *region,
                                          uint8_t value) {
    if (!ctx || !region || !ctx->progressiveLowQualityTiles) return;
    UINT32 rectCount = 0;
    const RECTANGLE_16 *rects = region16_rects(region, &rectCount);
    for (UINT32 i = 0; i < rectCount; i++) {
        uint32_t tx0 = rects[i].left / 64u;
        uint32_t ty0 = rects[i].top / 64u;
        uint32_t tx1 = (rects[i].right + 63u) / 64u;
        uint32_t ty1 = (rects[i].bottom + 63u) / 64u;
        if (tx1 > ctx->progressiveTileColumns) tx1 = ctx->progressiveTileColumns;
        if (ty1 > ctx->progressiveTileRows) ty1 = ctx->progressiveTileRows;
        for (uint32_t ty = ty0; ty < ty1; ty++)
            memset(ctx->progressiveLowQualityTiles +
                       (size_t)ty * ctx->progressiveTileColumns + tx0,
                   value, tx1 - tx0);
    }
}

static uint32_t progressive_count_low_quality_tiles(
    const RDPPeerContext *ctx) {
    if (!ctx || !ctx->progressiveLowQualityTiles) return 0u;
    const size_t tileCount = (size_t)ctx->progressiveTileColumns *
                             ctx->progressiveTileRows;
    uint32_t marked = 0u;
    for (size_t i = 0; i < tileCount; i++)
        marked += ctx->progressiveLowQualityTiles[i] ? 1u : 0u;
    return marked;
}

/* Select a circular, bounded subset of reduced-quality tiles. The bitmap is
 * not cleared here: only a successfully submitted full-quality frame is
 * allowed to retire refinement work. */
static bool progressive_build_refinement_batch(RDPPeerContext *ctx,
                                               uint32_t width,
                                               uint32_t height,
                                               uint32_t tileBudget,
                                               REGION16 *region,
                                               uint32_t *selectedTiles) {
    if (selectedTiles) *selectedTiles = 0u;
    if (!ctx || !ctx->progressiveTileMask ||
        !ctx->progressiveLowQualityTiles || !region || !tileBudget)
        return false;

    const size_t tileCount = (size_t)ctx->progressiveTileColumns *
                             ctx->progressiveTileRows;
    if (!tileCount) return true;
    memset(ctx->progressiveTileMask, 0, tileCount);
    const size_t start = ctx->progressiveRefinementCursor % tileCount;
    size_t scanned = 0u;
    uint32_t selected = 0u;
    for (; scanned < tileCount && selected < tileBudget; scanned++) {
        const size_t index = (start + scanned) % tileCount;
        if (!ctx->progressiveLowQualityTiles[index]) continue;
        ctx->progressiveTileMask[index] = 1u;
        selected++;
    }
    ctx->progressiveRefinementCursor =
        (uint32_t)((start + scanned) % tileCount);
    if (!selected) return true;
    return progressive_region_from_tile_mask(
        ctx, ctx->progressiveTileMask, width, height, region, selectedTiles);
}

static uint32_t progressive_refinement_tile_budget(RDPPeerContext *ctx,
                                                   uint32_t targetBytesPerSec) {
    uint32_t maxTiles = ctx && ctx->progressiveRefineMaxTiles
        ? ctx->progressiveRefineMaxTiles : 96u;
    const uint32_t lastBytes = atomic_load_explicit(
        &ctx->progressiveLastFrameBytes, memory_order_acquire);
    const uint32_t lastTiles = atomic_load_explicit(
        &ctx->progressiveLastFrameTiles, memory_order_acquire);
    uint32_t bytesPerTile = lastTiles
        ? (lastBytes + lastTiles - 1u) / lastTiles : 512u;
    if (bytesPerTile < 128u) bytesPerTile = 128u;
    if (bytesPerTile > 4096u) bytesPerTile = 4096u;

    uint32_t intervalMS = atomic_load_explicit(
        &ctx->progressiveFrameIntervalMS, memory_order_acquire);
    if (!intervalMS) intervalMS = 16u;
    uint64_t frameBytes = ((uint64_t)targetBytesPerSec * intervalMS) / 1000u;
    if (frameBytes < 8192u) frameBytes = 8192u;
    if (frameBytes > 65536u) frameBytes = 65536u;
    uint32_t tiles = (uint32_t)(frameBytes / bytesPerTile);
    if (tiles < 8u) tiles = 8u;
    if (tiles > maxTiles) tiles = maxTiles;
    return tiles;
}

/* QoE frame ACKs are cumulative evidence that the client rendered through a
 * frame. Reconstruct the exact compressed bytes after the newest ACK from the
 * bounded publication ring. Missing/overwritten history is treated as a full
 * window so uncertainty cannot create an unbounded WAN queue. */
static uint64_t progressive_qoe_inflight_bytes(const RDPPeerContext *ctx,
                                               uint32_t acknowledgedFrame,
                                               uint32_t sentFrame,
                                               bool *historyComplete) {
    if (historyComplete) *historyComplete = true;
    if (!ctx) return 0u;
    const uint32_t lag = sentFrame - acknowledgedFrame;
    if (!lag) return 0u;
    if (lag >= RDP_QOE_SEND_HISTORY) {
        if (historyComplete) *historyComplete = false;
        return UINT64_MAX;
    }

    uint64_t bytes = 0u;
    for (uint32_t offset = 1u; offset <= lag; offset++) {
        const uint32_t frameId = acknowledgedFrame + offset;
        const uint32_t slot = frameId % RDP_QOE_SEND_HISTORY;
        if (atomic_load_explicit(&ctx->qoeSendFrameIds[slot],
                                 memory_order_acquire) != frameId) {
            if (historyComplete) *historyComplete = false;
            return UINT64_MAX;
        }
        const uint32_t frameBytes = atomic_load_explicit(
            &ctx->qoeSendSizes[slot], memory_order_relaxed);
        if (UINT64_MAX - bytes < frameBytes) return UINT64_MAX;
        bytes += frameBytes;
    }
    return bytes;
}

static bool progressive_filter_changed_tiles(RDPPeerContext *ctx,
                                             const BYTE *base, size_t sourceStride,
                                             uint32_t width, uint32_t height,
                                             const REGION16 *metadataDamage,
                                             REGION16 *changedDamage,
                                             uint32_t *candidateTiles,
                                             uint32_t *changedTiles) {
    if (candidateTiles) *candidateTiles = 0;
    if (changedTiles) *changedTiles = 0;
    if (!ctx || !base || !metadataDamage || !changedDamage) return false;

    if (!ctx->progressiveReferencePixels || !ctx->progressiveTileMask ||
        ctx->progressiveTileColumns == 0 || ctx->progressiveTileRows == 0) {
        return region16_copy(changedDamage, metadataDamage) ? true : false;
    }

    size_t tileCount = (size_t)ctx->progressiveTileColumns *
                       (size_t)ctx->progressiveTileRows;
    memset(ctx->progressiveTileMask, 0, tileCount);

    UINT32 rectCount = 0;
    const RECTANGLE_16 *rects = region16_rects(metadataDamage, &rectCount);
    for (UINT32 i = 0; i < rectCount; i++) {
        uint32_t tx0 = rects[i].left / 64u;
        uint32_t ty0 = rects[i].top / 64u;
        uint32_t tx1 = (rects[i].right + 63u) / 64u;
        uint32_t ty1 = (rects[i].bottom + 63u) / 64u;
        if (tx1 > ctx->progressiveTileColumns) tx1 = ctx->progressiveTileColumns;
        if (ty1 > ctx->progressiveTileRows) ty1 = ctx->progressiveTileRows;
        for (uint32_t ty = ty0; ty < ty1; ty++) {
            for (uint32_t tx = tx0; tx < tx1; tx++)
                ctx->progressiveTileMask[(size_t)ty * ctx->progressiveTileColumns + tx] = 1;
        }
    }

    for (uint32_t ty = 0; ty < ctx->progressiveTileRows; ty++) {
        for (uint32_t tx = 0; tx < ctx->progressiveTileColumns; tx++) {
            size_t tileIndex = (size_t)ty * ctx->progressiveTileColumns + tx;
            if (!ctx->progressiveTileMask[tileIndex]) continue;
            if (candidateTiles) (*candidateTiles)++;

            uint32_t left = tx * 64u;
            uint32_t top = ty * 64u;
            uint32_t right = left + 64u;
            uint32_t bottom = top + 64u;
            if (right > width) right = width;
            if (bottom > height) bottom = height;

            bool changed = !ctx->progressiveReferenceValid;
            size_t rowBytes = (size_t)(right - left) * 4u;
            if (!changed) {
                for (uint32_t y = top; y < bottom; y++) {
                    const BYTE *src = base + (size_t)y * sourceStride +
                                      (size_t)left * 4u;
                    const BYTE *ref = ctx->progressiveReferencePixels +
                                      (size_t)y * ctx->progressiveReferenceStride +
                                      (size_t)left * 4u;
                    if (memcmp(src, ref, rowBytes) != 0) {
                        changed = true;
                        break;
                    }
                }
            }
            if (!changed) {
                ctx->progressiveTileMask[tileIndex] = 0;
                continue;
            }
            if (changedTiles) (*changedTiles)++;
        }
    }
    return progressive_region_from_tile_mask(ctx, ctx->progressiveTileMask,
                                             width, height, changedDamage, NULL);
}

static void progressive_update_reference(RDPPeerContext *ctx,
                                         const BYTE *base, size_t sourceStride,
                                         const REGION16 *sentDamage) {
    if (!ctx || !base || !sentDamage || !ctx->progressiveReferencePixels) return;
    UINT32 rectCount = 0;
    const RECTANGLE_16 *rects = region16_rects(sentDamage, &rectCount);
    for (UINT32 i = 0; i < rectCount; i++) {
        size_t rowBytes = (size_t)(rects[i].right - rects[i].left) * 4u;
        for (uint32_t y = rects[i].top; y < rects[i].bottom; y++) {
            const BYTE *src = base + (size_t)y * sourceStride +
                              (size_t)rects[i].left * 4u;
            BYTE *dst = ctx->progressiveReferencePixels +
                        (size_t)y * ctx->progressiveReferenceStride +
                        (size_t)rects[i].left * 4u;
            memcpy(dst, src, rowBytes);
        }
    }
    ctx->progressiveReferenceValid = true;
}

bool rdp_peer_send_progressive_frame(freerdp_peer *peer,
                                      IOSurfaceRef surface,
                                      uint32_t width, uint32_t height,
                                      const RECTANGLE_16 *dirtyRects,
                                      uint32_t dirtyRectCount,
                                      uint32_t *changedTilesOut) {
    if (changedTilesOut) *changedTilesOut = 0;
    if (!peer || !peer->context || !surface) return false;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->gfxReady || !ctx->gfx ||
        ctx->graphicsMode != RDPGraphicsModeProgressive ||
        !ctx->progressiveCodec)
        return false;
    if (ctx->outputSuppressed) return true;

    if (width != ctx->surfaceWidth || height != ctx->surfaceHeight ||
        width == 0 || height == 0 || width > UINT16_MAX || height > UINT16_MAX)
        return false;

    REGION16 invalid;
    region16_init(&invalid);
    bool regionOK = true;
    for (uint32_t i = 0; dirtyRects && i < dirtyRectCount; i++) {
        if (!progressive_region_add_rect(&invalid, &dirtyRects[i], width, height)) {
            regionOK = false;
            break;
        }
    }
    if (regionOK && region16_is_empty(&invalid)) {
        RECTANGLE_16 full = { .left = 0, .top = 0,
                              .right = (UINT16)width, .bottom = (UINT16)height };
        regionOK = region16_union_rect(&invalid, &invalid, &full) ? true : false;
    }
    if (!regionOK) {
        region16_uninit(&invalid);
        return false;
    }

    /* QoE ACKs report frames that Windows App has actually decoded/rendered.
     * During large desktop motion the client can suspend ordinary Frame ACKs
     * yet fall hundreds of QoE frames behind even though the local TLS socket
     * remains writable. Do not feed that private client queue indefinitely:
     * retain/union the newest damage, and resume with the latest desktop state
     * as soon as the client catches up. This is sampling/backpressure rather
     * than waiting synchronously for an ACK, so the peer/input loop never
     * blocks. Before the first QoE ACK, leave negotiation/initial paint alone. */
    const uint64_t qoeAcks = atomic_load_explicit(&ctx->qoeAckCount,
                                                  memory_order_acquire);
    const uint32_t qoeFrame = atomic_load_explicit(&ctx->lastQoeFrameId,
                                                   memory_order_acquire);
    const uint32_t frameAck = atomic_load_explicit(&ctx->lastAckFrameId,
                                                   memory_order_acquire);
    const bool frameAckSeen = atomic_load_explicit(&ctx->gfxAckSeen,
                                                   memory_order_acquire);
    const uint32_t feedbackFrame = rdp_tcp_latency_latest_feedback_frame(
        qoeFrame, frameAck, frameAckSeen);
    const uint32_t sentBeforeQoeGate = ctx->frameId;
    const uint32_t qoeLag = sentBeforeQoeGate - feedbackFrame;
    const uint32_t currentTargetBps = atomic_load_explicit(
        &ctx->progressiveTargetBytesPerSec, memory_order_acquire);
    const uint32_t lastQoeFeedbackMS = atomic_load_explicit(
        &ctx->lastQoeFeedbackMS, memory_order_acquire);
    const uint32_t progressiveBaseRTTMS = atomic_load_explicit(
        &ctx->progressiveBaseRTTMS, memory_order_acquire);
    const uint32_t qoeInflightBudget = rdp_tcp_latency_inflight_budget(
        currentTargetBps, progressiveBaseRTTMS, lastQoeFeedbackMS);
    bool qoeHistoryComplete = true;
    const uint64_t qoeInflightBytes = progressive_qoe_inflight_bytes(
        ctx, feedbackFrame, sentBeforeQoeGate, &qoeHistoryComplete);
    const uint32_t qoeFrameSafetyLimit =
        rdp_tcp_latency_qoe_frame_limit(
            ctx->tcpLatency.explicitMaxInflightFrames,
            qoeInflightBytes, qoeInflightBudget);
    if (qoeAcks > 0 &&
        (!qoeHistoryComplete || qoeInflightBytes >= qoeInflightBudget ||
         qoeLag >= qoeFrameSafetyLimit)) {
        progressive_accumulate_region(ctx, &invalid, width, height);
        uint64_t dropped = atomic_fetch_add_explicit(
            &ctx->progressiveQoeDrops, 1, memory_order_relaxed) + 1u;
        if (dropped == 1u || (dropped % 120u) == 0u) {
            rdp_info("Progressive QoE gate: lag=%u/%u frames, in-flight="
                     "%llu/%u bytes (history=%s), coalescing newest damage; "
                     "skipped=%llu",
                     qoeLag, qoeFrameSafetyLimit,
                     (unsigned long long)qoeInflightBytes, qoeInflightBudget,
                     qoeHistoryComplete ? "complete" : "missing",
                     (unsigned long long)dropped);
        }
        region16_uninit(&invalid);
        return true;
    }

    /* Never build a second large Progressive PDU while the previous logical
     * frame is still awaiting the client's decode ACK. ScreenCapture keeps and
     * unions the newest damage while this returns, so skipping here reduces
     * latency rather than losing the final desktop state. Before the first ACK
     * allow exactly one frame; a client that suspends ACKs explicitly disables
     * this gate as required by MS-RDPEGFX. */
    const bool ackSuspended = atomic_load_explicit(&ctx->gfxAckSuspended,
                                                   memory_order_acquire);
    const uint32_t acked = atomic_load_explicit(&ctx->lastAckFrameId,
                                                memory_order_acquire);
    const uint32_t sent = ctx->frameId;
    if (!ackSuspended && sent > acked) {
        progressive_accumulate_region(ctx, &invalid, width, height);
        atomic_fetch_add_explicit(&ctx->progressiveAckDrops, 1,
                                  memory_order_relaxed);
        region16_uninit(&invalid);
        return true;
    }

    /* Byte-based pacing is deliberately independent of ACK mode. Windows App
     * periodically sends SUSPEND_FRAME_ACKNOWLEDGEMENT, but that must not turn
     * a 20 Mbit/s WAN budget back into an unbounded 30fps producer. */
    const uint64_t nowMS = GetTickCount64();
    if (nowMS < ctx->progressiveNextSendMS) {
        progressive_accumulate_region(ctx, &invalid, width, height);
        atomic_fetch_add_explicit(&ctx->progressivePacingDrops, 1,
                                  memory_order_relaxed);
        region16_uninit(&invalid);
        return true;
    }

    /* A channel flush can hold xportLock for hundreds of milliseconds on a
     * constrained FRP/TCP path. If it is already busy, skip before burning CPU.
     * Once acquired, keep the lock through compression + submit: Progressive's
     * codec context is stateful, so compressing and then dropping a frame would
     * advance server state without advancing the client's decoder state. At the
     * measured 10-25ms encode time this bounded input delay is preferable to a
     * corrupt or gradually diverging Progressive surface. */
    if (pthread_mutex_trylock(&ctx->xportLock) != 0) {
        progressive_accumulate_region(ctx, &invalid, width, height);
        atomic_fetch_add_explicit(&ctx->progressiveBusyDrops, 1,
                                  memory_order_relaxed);
        region16_uninit(&invalid);
        return true;
    }

    /* Do not add another stateful Progressive PDU behind encrypted bytes that
     * FreeRDP could not yet hand to the socket. Make one non-blocking drain
     * attempt while we own the transport; if it is still blocked, preserve the
     * union of all damage and let the next capture callback send only the newest
     * desktop state. This is the crucial latency behavior on a variable FRP/WAN
     * path: old video frames are disposable, input and the latest frame are not. */
    if (peer->IsWriteBlocked && peer->IsWriteBlocked(peer)) {
        atomic_store_explicit(&ctx->transportWriteBlocked, true,
                              memory_order_release);
        atomic_fetch_add_explicit(&ctx->transportDrainAttempts, 1,
                                  memory_order_relaxed);
        int drainRc = peer->DrainOutputBuffer
            ? peer->DrainOutputBuffer(peer) : 1;
        if (drainRc < 0) {
            atomic_fetch_add_explicit(&ctx->transportDrainErrors, 1,
                                      memory_order_relaxed);
            progressive_accumulate_region(ctx, &invalid, width, height);
            pthread_mutex_unlock(&ctx->xportLock);
            region16_uninit(&invalid);
            rdp_error("FreeRDP transport output drain failed before Progressive frame");
            return false;
        }
        if (drainRc > 0) {
            atomic_fetch_add_explicit(&ctx->transportDrainStillBlocked, 1,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&ctx->progressiveTransportDrops, 1,
                                      memory_order_relaxed);
            progressive_accumulate_region(ctx, &invalid, width, height);
            pthread_mutex_unlock(&ctx->xportLock);
            region16_uninit(&invalid);
            return true;
        }
        atomic_store_explicit(&ctx->transportWriteBlocked, false,
                              memory_order_release);
    }
    if (!progressive_region_union(&invalid, &ctx->progressivePendingRegion,
                                  width, height)) {
        progressive_accumulate_region(ctx, &invalid, width, height);
        pthread_mutex_unlock(&ctx->xportLock);
        region16_uninit(&invalid);
        return false;
    }

    /* The reference starts at the client's initial black surface. Force the
     * first submitted frame to cover the whole desktop so future tile compares
     * have a complete, authoritative baseline. */
    if (ctx->progressiveReferencePixels && !ctx->progressiveReferenceValid) {
        RECTANGLE_16 full = { .left = 0, .top = 0,
                              .right = (UINT16)width, .bottom = (UINT16)height };
        region16_clear(&invalid);
        if (!region16_union_rect(&invalid, &invalid, &full)) {
            pthread_mutex_unlock(&ctx->xportLock);
            region16_uninit(&invalid);
            return false;
        }
    }

    const uint64_t encodeStart = GetTickCount64();

    IOReturn lockRc = IOSurfaceLock(surface, kIOSurfaceLockReadOnly, NULL);
    if (lockRc != kIOReturnSuccess) {
        rdp_error("IOSurfaceLock failed: 0x%x", lockRc);
        progressive_accumulate_region(ctx, &invalid, width, height);
        pthread_mutex_unlock(&ctx->xportLock);
        region16_uninit(&invalid);
        return false;
    }

    BYTE *base = (BYTE *)IOSurfaceGetBaseAddress(surface);
    size_t strideSize = IOSurfaceGetBytesPerRow(surface);
    REGION16 filtered;
    region16_init(&filtered);
    uint32_t candidateTiles = 0;
    uint32_t changedTiles = 0;
    bool filteredOK = base && strideSize <= UINT32_MAX &&
        progressive_filter_changed_tiles(ctx, base, strideSize, width, height,
                                         &invalid, &filtered,
                                         &candidateTiles, &changedTiles);
    if (filteredOK && changedTilesOut) *changedTilesOut = changedTiles;
    if (!filteredOK) {
        progressive_accumulate_region(ctx, &invalid, width, height);
        region16_uninit(&filtered);
        IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
        pthread_mutex_unlock(&ctx->xportLock);
        region16_uninit(&invalid);
        rdp_error("Progressive tile filtering failed");
        return false;
    }

    uint8_t encodedQuantStep = 0;
#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
    const uint32_t totalTiles = ctx->progressiveTileColumns &&
                                ctx->progressiveTileRows
        ? ctx->progressiveTileColumns * ctx->progressiveTileRows
        : ((width + 63u) / 64u) * ((height + 63u) / 64u);
    const uint32_t qualityTargetBps = atomic_load_explicit(
        &ctx->progressiveTargetBytesPerSec, memory_order_acquire);
    const RDPProgressiveQualityDecision qualityDecision =
        rdp_progressive_quality_update(&ctx->progressiveQuality,
                                       changedTiles, totalTiles,
                                       qualityTargetBps, GetTickCount64());
    if (qualityDecision.changed) {
        if (!progressive_apply_quant_step(ctx, qualityDecision.quantStep)) {
            ctx->progressiveQuality.enabled = false;
            rdp_error("Progressive motion quantization update failed; "
                      "adaptive quality disabled for this session");
        } else if (qualityDecision.restoreFullFrame) {
            rdp_info("Progressive motion quality: full quality restored; "
                     "%u tile(s) queued for budgeted refinement "
                     "(switches=%llu)",
                     progressive_count_low_quality_tiles(ctx),
                     (unsigned long long)ctx->progressiveQuality.switchCount);
        } else {
            rdp_info("Progressive motion quality: quant +%u for %u/%u changed "
                     "tiles at %.1f Mbit/s (switches=%llu)",
                     qualityDecision.quantStep, changedTiles, totalTiles,
                     (double)qualityTargetBps * 8.0 / 1000000.0,
                     (unsigned long long)ctx->progressiveQuality.switchCount);
        }
    }

    /* Refinement is background work, not another full-screen frame. Add only
     * one byte-budgeted tile batch while the rendered-frame queue is healthy.
     * If motion or QoE delay returns, leave the bitmap intact and resume later. */
    uint32_t refinementTiles = 0u;
    if (ctx->progressiveQuality.enabled &&
        ctx->progressiveQuality.appliedQuantStep == 0u &&
        !qualityDecision.largeMotion && ctx->progressiveLowQualityTiles) {
        const uint32_t queuedTiles =
            progressive_count_low_quality_tiles(ctx);
        uint32_t refinementFeedbackLimitMS = progressiveBaseRTTMS >= 125u
            ? 500u : progressiveBaseRTTMS * 4u;
        if (refinementFeedbackLimitMS < 250u)
            refinementFeedbackLimitMS = 250u;
        if (refinementFeedbackLimitMS > 500u)
            refinementFeedbackLimitMS = 500u;
        const bool refinementQueueHealthy = qoeAcks == 0u ||
            (qoeLag <= 1u &&
             (!lastQoeFeedbackMS ||
              lastQoeFeedbackMS <= refinementFeedbackLimitMS));
        if (queuedTiles && refinementQueueHealthy) {
            const uint32_t tileBudget = progressive_refinement_tile_budget(
                ctx, qualityTargetBps);
            REGION16 refinement;
            region16_init(&refinement);
            const bool refinementOK = progressive_build_refinement_batch(
                ctx, width, height, tileBudget, &refinement,
                &refinementTiles);
            if (!refinementOK ||
                !progressive_region_union(&filtered, &refinement,
                                          width, height)) {
                progressive_accumulate_region(ctx, &invalid, width, height);
                region16_uninit(&refinement);
                region16_uninit(&filtered);
                IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
                pthread_mutex_unlock(&ctx->xportLock);
                region16_uninit(&invalid);
                return false;
            }
            region16_uninit(&refinement);
            candidateTiles += refinementTiles;
            changedTiles += refinementTiles;
            ctx->progressiveRefinementBatches++;
            if (qualityDecision.restoreFullFrame ||
                (ctx->progressiveRefinementBatches % 8u) == 1u ||
                refinementTiles >= queuedTiles) {
                rdp_info("Progressive refinement batch: %u/%u queued tile(s), "
                         "budget=%u, QoE lag=%u feedback=%ums",
                         refinementTiles, queuedTiles, tileBudget, qoeLag,
                         lastQoeFeedbackMS);
            }
        }
    }
    if (changedTilesOut) *changedTilesOut = changedTiles;
    encodedQuantStep = ctx->progressiveQuality.appliedQuantStep;
#endif

    if (region16_is_empty(&filtered)) {
        region16_clear(&ctx->progressivePendingRegion);
        ctx->progressiveUnchangedFrames++;
        if ((ctx->progressiveUnchangedFrames % 120u) == 0u) {
            rdp_info("Progressive tile filter: skipped %llu unchanged frame(s), "
                     "last candidates=%u",
                     (unsigned long long)ctx->progressiveUnchangedFrames,
                     candidateTiles);
        }
        uint32_t activeIntervalMS = atomic_load_explicit(
            &ctx->progressiveFrameIntervalMS, memory_order_acquire);
        ctx->progressiveNextSendMS = GetTickCount64() + activeIntervalMS;
        region16_uninit(&filtered);
        IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
        pthread_mutex_unlock(&ctx->xportLock);
        region16_uninit(&invalid);
        return true;
    }

    UINT32 encodedRectCount = 0;
    (void)region16_rects(&filtered, &encodedRectCount);
    RECTANGLE_16 encodedExtents = *region16_extents(&filtered);
    uint64_t encodedPixels = progressive_region_pixels(&filtered);
    bool encoded = false;
    BYTE *compressed = NULL;
    UINT32 compressedLen = 0;
    int rc = progressive_compress(
        (PROGRESSIVE_CONTEXT *)ctx->progressiveCodec,
        base, (UINT32)(strideSize * height), PIXEL_FORMAT_BGRA32,
        width, height, (UINT32)strideSize, &filtered,
        &compressed, &compressedLen);
    encoded = (rc > 0 && compressed && compressedLen > 0);
    if (!encoded)
        rdp_error("progressive_compress failed: %d", rc);
    if (!encoded) {
        progressive_accumulate_region(ctx, &filtered, width, height);
        region16_uninit(&filtered);
        IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
        pthread_mutex_unlock(&ctx->xportLock);
        region16_uninit(&invalid);
        return false;
    }
    const uint64_t encodeEnd = GetTickCount64();

    RDPGFX_SURFACE_COMMAND cmd = {0};
    cmd.surfaceId = ctx->surfaceId;
    cmd.codecId = RDPGFX_CODECID_CAPROGRESSIVE;
    cmd.format = PIXEL_FORMAT_BGRX32;
    cmd.left = 0;
    cmd.top = 0;
    cmd.right = width;
    cmd.bottom = height;
    cmd.width = width;
    cmd.height = height;
    cmd.length = compressedLen;
    cmd.data = compressed;

    uint32_t fid = ++ctx->frameId;
    RDPGFX_START_FRAME_PDU startFrame = { .frameId = fid };
    RDPGFX_END_FRAME_PDU endFrame = { .frameId = fid };
    const uint32_t qoeSlot = fid % RDP_QOE_SEND_HISTORY;
    atomic_store_explicit(&ctx->qoeSendTimesMS[qoeSlot], GetTickCount64(),
                          memory_order_relaxed);
    atomic_store_explicit(&ctx->qoeSendSizes[qoeSlot], compressedLen,
                          memory_order_relaxed);
    atomic_store_explicit(&ctx->qoeSendFrameIds[qoeSlot], fid,
                          memory_order_release);
    UINT sendRc = ctx->gfx->SurfaceFrameCommand(ctx->gfx, &cmd,
                                                 &startFrame, &endFrame);
    const bool writeBlockedAfterSubmit = peer->IsWriteBlocked &&
        peer->IsWriteBlocked(peer);
    atomic_store_explicit(&ctx->transportWriteBlocked,
                          writeBlockedAfterSubmit, memory_order_release);
    pthread_mutex_unlock(&ctx->xportLock);
    const uint64_t sendEnd = GetTickCount64();
    if (sendRc != CHANNEL_RC_OK) {
        progressive_accumulate_region(ctx, &filtered, width, height);
        region16_uninit(&filtered);
        IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
        region16_uninit(&invalid);
        rdp_error("Progressive SurfaceFrameCommand failed: %u", sendRc);
        return false;
    }
    progressive_update_reference(ctx, base, strideSize, &filtered);
    progressive_set_quality_tiles(ctx, &filtered,
                                  encodedQuantStep > 0 ? 1u : 0u);
    region16_uninit(&filtered);
    IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
    region16_clear(&ctx->progressivePendingRegion);
    region16_uninit(&invalid);
    atomic_store_explicit(&ctx->progressiveLastFrameBytes, compressedLen,
                          memory_order_release);
    atomic_store_explicit(&ctx->progressiveLastFrameTiles, changedTiles,
                          memory_order_release);
#if defined(MACOS_RDP_UDP_PATCHED_FREERDP)
    if (refinementTiles > 0u &&
        progressive_count_low_quality_tiles(ctx) == 0u) {
        rdp_info("Progressive refinement complete after %llu batch(es)",
                 (unsigned long long)ctx->progressiveRefinementBatches);
    }
#endif

    uint32_t targetBps = atomic_load_explicit(
        &ctx->progressiveTargetBytesPerSec, memory_order_acquire);
    uint64_t intervalMS = targetBps
        ? ((uint64_t)compressedLen * 1000u + targetBps - 1u) / targetBps
        : 33u;
    const uint32_t activeIntervalMS = atomic_load_explicit(
        &ctx->progressiveFrameIntervalMS, memory_order_acquire);
    if (intervalMS < activeIntervalMS)
        intervalMS = activeIntervalMS;
    if (intervalMS > 1000u) intervalMS = 1000u;
    /* Charge pacing from the beginning of this frame's work, not from the end.
     * With a capture-paced source, adding a full frame delay after encode
     * caused every next capture callback to arrive slightly early and be
     * discarded, unintentionally limiting tiny updates to about 15 fps. The
     * source itself remains capped; large packets still receive their
     * full byte-budget interval without double-charging encode time. */
    uint64_t nextSend = encodeStart + intervalMS;
    ctx->progressiveNextSendMS = nextSend > sendEnd ? nextSend : sendEnd;

    const uint64_t encodeMS = encodeEnd - encodeStart;
    const uint64_t submitMS = sendEnd - encodeEnd;
    const uint32_t statsFrameRate = atomic_load_explicit(
        &ctx->progressiveFrameRate, memory_order_acquire);
    const uint32_t statsCadence = statsFrameRate ? statsFrameRate : 30u;
    if ((fid % statsCadence) == 0u || compressedLen >= 49152u ||
        changedTiles >= 64u || encodeMS >= 250u || submitMS >= 250u) {
        const bool ackSeen = atomic_load_explicit(&ctx->gfxAckSeen,
                                                  memory_order_acquire);
        const bool ackIsSuspended = atomic_load_explicit(
            &ctx->gfxAckSuspended, memory_order_acquire);
        const uint64_t lastAckMS = atomic_load_explicit(
            &ctx->lastAckTimestampMS, memory_order_acquire);
        const uint64_t ackAgeMS = ackSeen && sendEnd >= lastAckMS
            ? sendEnd - lastAckMS : 0;
        rdp_info("Progressive stats: sent=%u ack=%u tiles=%u/%u rects=%u "
                 "pixels=%llu "
                 "bounds=(%u,%u)-(%u,%u) len=%u encode=%llums submit=%llums "
                 "target=%.1fMbit qoe-window=%llu/%uB "
                 "ack-gated=%llu qoe-gated=%llu paced=%llu "
                 "transport-busy=%llu transport-dropped=%llu "
                 "wire-blocked=%d drain=%llu/%llu/%llu "
                 "ack-mode=%s ack-age=%llums decoded=%u client-queue=%u "
                 "qoe-frame=%u qoe-feedback=%ums qoe-decode=%ums "
                 "qoe-render=%ums",
                 fid,
                 atomic_load_explicit(&ctx->lastAckFrameId, memory_order_acquire),
                 changedTiles, candidateTiles,
                 encodedRectCount, (unsigned long long)encodedPixels,
                 encodedExtents.left, encodedExtents.top,
                 encodedExtents.right, encodedExtents.bottom, compressedLen,
                 (unsigned long long)encodeMS,
                 (unsigned long long)submitMS,
                 (double)targetBps * 8.0 / 1000000.0,
                 (unsigned long long)qoeInflightBytes, qoeInflightBudget,
                 (unsigned long long)atomic_load_explicit(
                     &ctx->progressiveAckDrops, memory_order_relaxed),
                 (unsigned long long)atomic_load_explicit(
                     &ctx->progressiveQoeDrops, memory_order_relaxed),
                 (unsigned long long)atomic_load_explicit(
                     &ctx->progressivePacingDrops, memory_order_relaxed),
                 (unsigned long long)atomic_load_explicit(
                     &ctx->progressiveBusyDrops, memory_order_relaxed),
                 (unsigned long long)atomic_load_explicit(
                     &ctx->progressiveTransportDrops, memory_order_relaxed),
                 atomic_load_explicit(&ctx->transportWriteBlocked,
                                      memory_order_acquire) ? 1 : 0,
                 (unsigned long long)atomic_load_explicit(
                     &ctx->transportDrainAttempts, memory_order_relaxed),
                 (unsigned long long)atomic_load_explicit(
                     &ctx->transportDrainStillBlocked, memory_order_relaxed),
                 (unsigned long long)atomic_load_explicit(
                     &ctx->transportDrainErrors, memory_order_relaxed),
                 ackIsSuspended ? "suspended" : (ackSeen ? "active" : "pending"),
                 (unsigned long long)ackAgeMS,
                 atomic_load_explicit(&ctx->lastAckTotalFramesDecoded,
                                      memory_order_relaxed),
                 atomic_load_explicit(&ctx->clientQueueDepth,
                                      memory_order_relaxed),
                 atomic_load_explicit(&ctx->lastQoeFrameId,
                                      memory_order_relaxed),
                 atomic_load_explicit(&ctx->lastQoeFeedbackMS,
                                      memory_order_relaxed),
                 atomic_load_explicit(&ctx->lastQoeDecodeSpanMS,
                                      memory_order_relaxed),
                 atomic_load_explicit(&ctx->lastQoeRenderMS,
                                      memory_order_acquire));
    }
    return true;
}

void rdp_peer_send_default_cursor(freerdp_peer *peer) {
    /* Without any pointer update, mstsc renders the cursor coupled to frame
     * redraws (jerky). Advertising the default SYSTEM pointer makes the client
     * draw + move the cursor locally at the mouse's native rate (smooth), like a
     * Windows RDP server. (Showing the actual Mac cursor shapes lag-free would
     * need full color-pointer PDUs built from the captured cursor — a follow-up.) */
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    rdpPointerUpdate *pointer = peer->context->update->pointer;
    if (!pointer || !pointer->PointerSystem) return;
    POINTER_SYSTEM_UPDATE sys = {0};
    sys.type = SYSPTR_DEFAULT;
    pthread_mutex_lock(&ctx->xportLock);
    pointer->PointerSystem(peer->context, &sys);
    pthread_mutex_unlock(&ctx->xportLock);
    rdp_verbose("sent default system pointer (client-side cursor)");
}

void rdp_peer_send_cursor_position(freerdp_peer *peer,
                                   uint16_t x, uint16_t y) {
    if (!peer || !peer->context) return;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->activated || ctx->outputSuppressed) return;

    rdpPointerUpdate *pointer = peer->context->update->pointer;
    if (!pointer || !pointer->PointerPosition) return;

    POINTER_POSITION_UPDATE pos = {
        .xPos = x,
        .yPos = y,
    };
    pthread_mutex_lock(&ctx->xportLock);
    BOOL ok = pointer->PointerPosition(peer->context, &pos);
    pthread_mutex_unlock(&ctx->xportLock);
    if (!ok)
        rdp_error("cursor position send failed at (%u,%u)", x, y);
}

/* Cursor cap from CursorCapture (kMaxCursorDim). */
#define RDP_CURSOR_NEW_MAX 96
#define RDP_CURSOR_COMPAT_CANVAS 64

/* Stable fingerprint for one client-side pointer cache entry. The source has
 * already been sanitized by CursorCapture, so hashing the exact BGRA payload
 * plus its geometry is sufficient to recognize a previously-defined shape. */
static uint64_t rdp_cursor_hash(const uint8_t *bgra, uint32_t w, uint32_t h,
                                uint16_t hotX, uint16_t hotY) {
    uint64_t hash = UINT64_C(1469598103934665603);
    const uint64_t prime = UINT64_C(1099511628211);
    const uint32_t geometry[] = { w, h, hotX, hotY };

    for (size_t i = 0; i < sizeof(geometry); i++) {
        hash ^= ((const uint8_t *)geometry)[i];
        hash *= prime;
    }
    for (size_t i = 0, len = (size_t)w * h * 4u; i < len; i++) {
        hash ^= bgra[i];
        hash *= prime;
    }
    return hash;
}

void rdp_peer_send_cursor_shape(freerdp_peer *peer,
                                const uint8_t *bgra, uint32_t w, uint32_t h,
                                uint16_t hotX, uint16_t hotY) {
    if (!peer || !bgra || w == 0 || h == 0) return;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;

    /* Don't push pointers before the client is up: pre-activation the update
     * channel isn't wired, and (like graphics) sends while output is suppressed
     * are pointless. Mirrors rdp_peer_send_h264_frame's readiness gate. */
    if (!ctx->activated) { rdp_debug("cursor: peer not activated"); return; }
    if (ctx->outputSuppressed) return;

    rdpPointerUpdate *pointer = peer->context->update->pointer;
    if (!pointer) return;

    /* Clamp hotspot inside the bitmap. */
    if (hotX >= w) hotX = (uint16_t)(w - 1);
    if (hotY >= h) hotY = (uint16_t)(h - 1);

    const uint64_t cursorHash = rdp_cursor_hash(bgra, w, h, hotX, hotY);
    const uint32_t sourceW = w;
    const uint32_t sourceH = h;

    /* macOS exposes tightly-cropped cursor bitmaps with many different small
     * dimensions (23x22 I-beam, 18x28 vertical resize, 22x22 diagonals, ...).
     * Windows App for iOS decodes some of those variable-width classic-pointer
     * masks incorrectly even though the outgoing bitmap is valid. The old
     * VNC->xrdp path avoided that client quirk by sending cursor images on a
     * fixed-size canvas. Reproduce that wire layout without changing a single
     * visible source pixel or the hotspot: only transparent right/bottom padding
     * is added. Shapes larger than 64px keep their captured dimensions. */
    if (w <= RDP_CURSOR_COMPAT_CANVAS && h <= RDP_CURSOR_COMPAT_CANVAS) {
        w = RDP_CURSOR_COMPAT_CANVAS;
        h = RDP_CURSOR_COMPAT_CANVAS;
    }

    /* PointerNew stores images in the negotiated pointer cache. Never address
     * beyond the size advertised by this client, even though the server offers
     * a larger cache in its own capability set. */
    uint32_t cacheSlots = freerdp_settings_get_uint32(
        peer->context->settings, FreeRDP_PointerCacheSize);
    if (cacheSlots == 0) cacheSlots = 1;
    if (cacheSlots > RDP_POINTER_CACHE_TRACKED)
        cacheSlots = RDP_POINTER_CACHE_TRACKED;

    /* ── Build the XOR (color) mask ───────────────────────────────────────
     * mstsc renders 32bpp/alpha color pointers UNRELIABLY (it draws nothing —
     * the cursor is invisible even though the PDUs are well-formed). We
     * therefore emit a CLASSIC 24bpp BGR color pointer, which mstsc renders
     * reliably (MS-RDPBCGR 2.2.9.1.1.4.4). Layout: 3 bytes/pixel (B,G,R, no
     * alpha), scanlines BOTTOM-UP, each row padded to a 2-byte (WORD) boundary.
     * Our input is top-down BGRA premultiplied, so we emit rows in reverse and
     * drop the alpha byte. Because alpha is premultiplied, (semi-)transparent
     * pixels are already darkened toward black; the AND mask masks them out, so
     * the dropped alpha costs nothing visible. */
    const uint32_t xorBpp = 24;
    uint32_t xorRowBytes = w * 3u;
    xorRowBytes = (xorRowBytes + 1u) & ~1u;          /* pad to 2 bytes (WORD) */
    uint32_t xorLen = xorRowBytes * h;

    /* ── Build the AND (transparency) mask ────────────────────────────────
     * 1bpp, BOTTOM-UP, each scanline padded to a 2-byte boundary. A SET bit
     * means "transparent" (client shows the underlying pixel). Derive it from
     * alpha: a (near-)transparent pixel -> transparent (bit 1), else opaque
     * (bit 0). We treat alpha < 128 as transparent so the dark fringe of
     * premultiplied anti-aliased edges is masked out rather than painted. */
    uint32_t andRowBytes = ((w + 7u) / 8u);
    andRowBytes = (andRowBytes + 1u) & ~1u;          /* pad to 2 bytes */
    uint32_t andLen = andRowBytes * h;

    /* calloc so the WORD-padding bytes at the end of each xor row stay 0. */
    uint8_t *xorData = (uint8_t *)calloc(1, xorLen);
    uint8_t *andData = (uint8_t *)calloc(1, andLen); /* default opaque (0) */
    if (!xorData || !andData) { free(xorData); free(andData); return; }

    for (uint32_t y = 0; y < h; y++) {
        const uint8_t *srcRow = y < sourceH
            ? bgra + (size_t)y * (sourceW * 4u)
            : NULL;
        /* bottom-up: source row y goes to dest row (h-1-y). */
        uint8_t *dstRow = xorData + (size_t)(h - 1 - y) * xorRowBytes;
        uint8_t *andRow = andData + (size_t)(h - 1 - y) * andRowBytes;
        for (uint32_t x = 0; x < w; x++) {
            uint8_t       *dpx = dstRow + (size_t)x * 3;   /* B,G,R   */
            const uint8_t *px = (srcRow && x < sourceW)
                ? srcRow + (size_t)x * 4u
                : NULL;                                    /* B,G,R,A */
            const uint8_t alpha = px ? px[3] : 0;
            if (alpha < 64) {    /* Match FreeRDP Shadow's alpha cutoff. */
                dpx[0] = dpx[1] = dpx[2] = 0;
                /* MSB-first bit order within each byte. */
                andRow[x / 8] |= (uint8_t)(0x80u >> (x % 8));
            } else if (alpha < 255) {
                /* CoreGraphics gives us premultiplied BGRA. RDP's classic
                 * 24-bpp XOR mask expects straight color channels. */
                dpx[0] = (uint8_t)(((uint32_t)px[0] * 255u) / alpha);
                dpx[1] = (uint8_t)(((uint32_t)px[1] * 255u) / alpha);
                dpx[2] = (uint8_t)(((uint32_t)px[2] * 255u) / alpha);
            } else {
                dpx[0] = px[0];
                dpx[1] = px[1];
                dpx[2] = px[2];
            }
        }
    }

    bool ok = false;
    bool cacheHit = false;
    uint16_t cacheSlot = 0;

    pthread_mutex_lock(&ctx->xportLock);
    for (uint16_t i = 0; i < cacheSlots; i++) {
        if (ctx->pointerCache[i].valid &&
            ctx->pointerCache[i].hash == cursorHash &&
            ctx->pointerCache[i].width == w &&
            ctx->pointerCache[i].height == h &&
            ctx->pointerCache[i].hotX == hotX &&
            ctx->pointerCache[i].hotY == hotY) {
            cacheHit = true;
            cacheSlot = i;
            break;
        }
    }

    if (cacheHit && pointer->PointerCached) {
        POINTER_CACHED_UPDATE cached = { .cacheIndex = cacheSlot };
        ok = pointer->PointerCached(peer->context, &cached) ? true : false;
        if (!ok)
            ctx->pointerCache[cacheSlot].valid = false;
    } else if (w <= RDP_CURSOR_NEW_MAX && h <= RDP_CURSOR_NEW_MAX) {
        /* Allocate a free negotiated slot, falling back to round-robin
         * replacement only after every slot is populated. PointerNew both
         * displays the image and stores it in the cache (MS-RDPBCGR 3.2.5.9.2),
         * so do not immediately follow it with a redundant PointerCached. That
         * back-to-back sequence is not emitted by xrdp and has produced corrupt
         * shapes in Windows App for iOS. PointerCached is used only on a later
         * revisit to an already-defined shape. */
        if (pointer->PointerNew) {
            cacheSlot = (uint16_t)(ctx->pointerCacheNext % cacheSlots);
            for (uint32_t n = 0; n < cacheSlots; n++) {
                const uint16_t candidate =
                    (uint16_t)((ctx->pointerCacheNext + n) % cacheSlots);
                if (!ctx->pointerCache[candidate].valid) {
                    cacheSlot = candidate;
                    break;
                }
            }

            POINTER_NEW_UPDATE upd = {0};
            upd.xorBpp = (UINT16)xorBpp;
            upd.colorPtrAttr.cacheIndex    = cacheSlot;
            upd.colorPtrAttr.hotSpotX      = hotX;
            upd.colorPtrAttr.hotSpotY      = hotY;
            upd.colorPtrAttr.width         = (UINT16)w;
            upd.colorPtrAttr.height        = (UINT16)h;
            upd.colorPtrAttr.lengthAndMask = (UINT16)andLen;
            upd.colorPtrAttr.lengthXorMask = (UINT16)xorLen;
            upd.colorPtrAttr.xorMaskData   = xorData;
            upd.colorPtrAttr.andMaskData   = andData;
            ok = pointer->PointerNew(peer->context, &upd) ? true : false;
            if (ok) {
                ctx->pointerCache[cacheSlot].hash = cursorHash;
                ctx->pointerCache[cacheSlot].width = (uint16_t)w;
                ctx->pointerCache[cacheSlot].height = (uint16_t)h;
                ctx->pointerCache[cacheSlot].hotX = hotX;
                ctx->pointerCache[cacheSlot].hotY = hotY;
                ctx->pointerCache[cacheSlot].valid = true;
                ctx->pointerCacheNext = (uint16_t)((cacheSlot + 1) % cacheSlots);
            }
        }
    } else if (pointer->PointerLarge) {
        cacheSlot = (uint16_t)(ctx->pointerCacheNext % cacheSlots);
        POINTER_LARGE_UPDATE upd = {0};
        upd.xorBpp        = (UINT16)xorBpp;
        upd.cacheIndex    = cacheSlot;
        upd.hotSpotX      = hotX;
        upd.hotSpotY      = hotY;
        upd.width         = (UINT16)w;
        upd.height        = (UINT16)h;
        upd.lengthAndMask = andLen;
        upd.lengthXorMask = xorLen;
        upd.xorMaskData   = xorData;
        upd.andMaskData   = andData;
        ok = pointer->PointerLarge(peer->context, &upd) ? true : false;
        if (ok) {
            ctx->pointerCache[cacheSlot].hash = cursorHash;
            ctx->pointerCache[cacheSlot].width = (uint16_t)w;
            ctx->pointerCache[cacheSlot].height = (uint16_t)h;
            ctx->pointerCache[cacheSlot].hotX = hotX;
            ctx->pointerCache[cacheSlot].hotY = hotY;
            ctx->pointerCache[cacheSlot].valid = true;
            ctx->pointerCacheNext = (uint16_t)((cacheSlot + 1) % cacheSlots);
        }
    }
    pthread_mutex_unlock(&ctx->xportLock);

    free(xorData);
    free(andData);

    if (!ok) {
        rdp_error("cursor %s failed cache[%u] (source=%ux%u wire=%ux%u)",
                  cacheHit ? "selection" : "definition", cacheSlot,
                  sourceW, sourceH, w, h);
    } else if (cacheHit) {
        rdp_verbose("selected cached cursor cache[%u] source=%ux%u wire=%ux%u "
                    "hot=(%u,%u)",
                    cacheSlot, sourceW, sourceH, w, h, hotX, hotY);
    } else {
        rdp_verbose("defined+displayed cursor cache[%u/%u] source=%ux%u "
                    "wire=%ux%u hot=(%u,%u) xorBpp=%u xor=%u and=%u",
                    cacheSlot, cacheSlots, sourceW, sourceH, w, h, hotX, hotY,
                    xorBpp, xorLen, andLen);
    }
}

bool rdp_peer_send_bitmap(freerdp_peer *peer,
                           const uint8_t *bgra, uint32_t x, uint32_t y,
                           uint32_t width, uint32_t height) {
    rdpUpdate *update = peer->context->update;
    SURFACE_BITS_COMMAND cmd = {0};
    cmd.destLeft             = (UINT16)x;
    cmd.destTop              = (UINT16)y;
    cmd.destRight            = (UINT16)(x + width);
    cmd.destBottom           = (UINT16)(y + height);
    cmd.bmp.bpp              = 32;
    cmd.bmp.width            = (UINT16)width;
    cmd.bmp.height           = (UINT16)height;
    cmd.bmp.bitmapData       = (BYTE *)bgra;
    cmd.bmp.bitmapDataLength = width * height * 4;
    cmd.bmp.codecID          = RDP_CODEC_ID_NONE;
    return update->SurfaceBits(update->context, &cmd);
}

bool rdp_peer_send_audio(freerdp_peer *peer,
                          const int16_t *samples, uint32_t frame_count) {
    if (!peer || !peer->context || !samples || frame_count == 0) return false;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->rdpsnd || !ctx->audioReady) return false;
    /* SendSamples(context, buf, nframes, timestamp) — real 3.x signature.
     * wTimestamp is a millisecond clock used by the client's Wave Confirm and
     * latency accounting. Reusing zero for every packet made all audio blocks
     * appear to share one capture time and is especially fragile on Windows
     * App; use the monotonic millisecond clock, modulo the 16-bit wire field. */
    UINT16 timestamp = (UINT16)(GetTickCount64() & 0xFFFFu);
    pthread_mutex_lock(&ctx->xportLock);
    UINT rc = ctx->rdpsnd->SendSamples(ctx->rdpsnd, samples, frame_count,
                                      timestamp);
    pthread_mutex_unlock(&ctx->xportLock);
    return rc == CHANNEL_RC_OK;
}

/* xportLock must be held: ServerFormatList writes to the shared RDP transport. */
static UINT clipboard_advertise_locked(RDPPeerContext *ctx, uint32_t format,
                                       const char *formatName) {
    /* formatName must never be NULL with FreeRDP long-format serialization.
     * Standard formats use an empty name; registered formats are mapped by the
     * UTF-16 name and may use any endpoint-local ID. */
    CLIPRDR_FORMAT fmt = {
        .formatId = (UINT32)format,
        .formatName = (char *)(formatName ? formatName : ""),
    };
    CLIPRDR_FORMAT_LIST list = {0};
    list.common.msgType = CB_FORMAT_LIST;
    list.common.msgFlags = 0;
    list.numFormats = 1;
    list.formats = &fmt;
    return ctx->cliprdr->ServerFormatList(ctx->cliprdr, &list);
}

bool rdp_peer_send_clipboard(freerdp_peer *peer,
                              const uint8_t *data, size_t len,
                              uint32_t format) {
    if (!peer || !peer->context || (!data && len > 0)) return false;
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->cliprdr) { rdp_verbose("no clipboard channel"); return false; }

    /* Store an owned copy. The bytes remain valid until the client later sends
     * its Format Data Request; clipboard file metadata uses the same slot. */
    uint8_t *newClipData = (uint8_t *)malloc(len ? len : 1);
    if (!newClipData) { rdp_verbose("clipboard: malloc failed"); return false; }
    if (len) memcpy(newClipData, data, len);

    uint8_t *oldClipData;
    char **oldFilePaths;
    uint64_t *oldFileSizes;
    uint32_t oldFileCount;
    UINT rc = CHANNEL_RC_OK;
    bool ready;
    pthread_mutex_lock(&ctx->xportLock);
    /* A genuine Mac-side copy supersedes an in-progress or previously
     * published Windows file clipboard. */
    clipboard_incoming_reset(ctx, true);
    oldClipData = ctx->clipData;
    oldFilePaths = ctx->clipFilePaths;
    oldFileSizes = ctx->clipFileSizes;
    oldFileCount = ctx->clipFileCount;
    ctx->clipData = newClipData;
    ctx->clipLen = len;
    ctx->clipFormat = format;
    ctx->clipFilePaths = NULL;
    ctx->clipFileSizes = NULL;
    ctx->clipFileCount = 0;
    ready = ctx->clipReady;
    if (ready) {
        const char *name = format == RDP_CLIPBOARD_FORMAT_PNG ? "PNG" : "";
        rc = clipboard_advertise_locked(ctx, format, name);
    }
    pthread_mutex_unlock(&ctx->xportLock);
    free(oldClipData);
    clipboard_file_set_free(oldFilePaths, oldFileSizes, oldFileCount);

    if (!ready) {
        rdp_verbose("clipboard: held %zu bytes (fmt 0x%08x) — channel not ready, "
                    "advertise deferred", len, format);
        return true;
    }
    rdp_verbose("clipboard: advertised format 0x%08x (%zu bytes, rc=%u)",
                format, len, rc);
    return rc == CHANNEL_RC_OK;
}

bool rdp_peer_send_clipboard_files(freerdp_peer *peer,
                                   const char *const *paths,
                                   size_t count) {
    if (!peer || !peer->context || !paths || count == 0 ||
        count > RDP_CLIPBOARD_FILE_MAX_COUNT) {
        rdp_verbose("clipboard: invalid file set count=%zu (maximum %u)",
                    count, RDP_CLIPBOARD_FILE_MAX_COUNT);
        return false;
    }
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->cliprdr) return false;

    char **newPaths = calloc(count, sizeof(*newPaths));
    uint64_t *newSizes = calloc(count, sizeof(*newSizes));
    FILEDESCRIPTORW *descriptors = calloc(count, sizeof(*descriptors));
    BYTE *descriptorData = NULL;
    UINT32 descriptorLen = 0;
    bool ok = false;
    if (!newPaths || !newSizes || !descriptors) goto cleanup;

    for (size_t i = 0; i < count; i++) {
        const char *path = paths[i];
        struct stat st = {0};
        if (!path || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_size < 0 || (uint64_t)st.st_size > UINT32_MAX) {
            rdp_info("clipboard: file copy currently accepts regular files up to "
                     "4 GiB only: '%s'", path ? path : "(null)");
            goto cleanup;
        }
        const char *name = strrchr(path, '/');
        name = name ? name + 1 : path;
        if (!*name || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            rdp_info("clipboard: unsafe or empty file name rejected: '%s'", path);
            goto cleanup;
        }

        size_t wideLen = 0;
        WCHAR *wideName = ConvertUtf8ToWCharAlloc(name, &wideLen);
        if (!wideName) goto cleanup;
        size_t actualWideLen = _wcslen(wideName);
        if (actualWideLen >= ARRAYSIZE(descriptors[i].cFileName)) {
            rdp_info("clipboard: file name is too long for RDP: '%s'", name);
            free(wideName);
            goto cleanup;
        }

        newPaths[i] = strdup(path);
        if (!newPaths[i]) {
            free(wideName);
            goto cleanup;
        }
        newSizes[i] = (uint64_t)st.st_size;
        descriptors[i].dwFlags = FD_ATTRIBUTES | FD_FILESIZE |
                                 FD_PROGRESSUI | FD_UNICODE;
        descriptors[i].dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
        descriptors[i].nFileSizeHigh = (DWORD)(newSizes[i] >> 32);
        descriptors[i].nFileSizeLow = (DWORD)newSizes[i];
        memcpy(descriptors[i].cFileName, wideName,
               (actualWideLen + 1) * sizeof(WCHAR));
        free(wideName);
    }

    UINT serializeRc = cliprdr_serialize_file_list(
        descriptors, (UINT32)count, &descriptorData, &descriptorLen);
    if (serializeRc != CHANNEL_RC_OK || !descriptorData || descriptorLen == 0) {
        rdp_info("clipboard: FileGroupDescriptorW serialization failed: %u",
                 serializeRc);
        goto cleanup;
    }

    uint8_t *oldClipData;
    char **oldFilePaths;
    uint64_t *oldFileSizes;
    uint32_t oldFileCount;
    UINT advertiseRc = CHANNEL_RC_OK;
    bool ready;
    bool streams;
    pthread_mutex_lock(&ctx->xportLock);
    clipboard_incoming_reset(ctx, true);
    oldClipData = ctx->clipData;
    oldFilePaths = ctx->clipFilePaths;
    oldFileSizes = ctx->clipFileSizes;
    oldFileCount = ctx->clipFileCount;
    ctx->clipData = descriptorData;
    ctx->clipLen = descriptorLen;
    ctx->clipFormat = RDP_CLIPBOARD_FORMAT_FILE_GROUP_DESCRIPTOR_W;
    ctx->clipFilePaths = newPaths;
    ctx->clipFileSizes = newSizes;
    ctx->clipFileCount = (uint32_t)count;
    descriptorData = NULL;
    newPaths = NULL;
    newSizes = NULL;
    ready = ctx->clipReady;
    streams = ctx->cliprdr->streamFileClipEnabled;
    if (ready && streams) {
        advertiseRc = clipboard_advertise_locked(
            ctx, RDP_CLIPBOARD_FORMAT_FILE_GROUP_DESCRIPTOR_W,
            "FileGroupDescriptorW");
    }
    pthread_mutex_unlock(&ctx->xportLock);
    free(oldClipData);
    clipboard_file_set_free(oldFilePaths, oldFileSizes, oldFileCount);

    if (!ready)
        rdp_verbose("clipboard: held %zu file(s) until CLIPRDR is ready", count);
    else if (!streams)
        rdp_info("clipboard: client did not negotiate stream file clipboard");
    else
        rdp_info("clipboard: advertised %zu file(s), descriptor=%u bytes rc=%u",
                 count, descriptorLen, advertiseRc);
    ok = !ready || (streams && advertiseRc == CHANNEL_RC_OK);

cleanup:
    free(descriptorData);
    clipboard_file_set_free(newPaths, newSizes, (uint32_t)count);
    free(descriptors);
    return ok;
}

/* ── RDPDR (MS-RDPEFS) drive-redirection implementation ─────────────────── */

/* Write a complete wStream PDU to the rdpdr WTS channel.
 * Called under xportLock (transport write). */
static bool rdpdr_write_pdu(HANDLE ch, wStream *s) {
    size_t len     = Stream_GetPosition(s);
    BYTE  *buf     = Stream_Buffer(s);
    ULONG  written = 0;
    BOOL   ok      = WTSVirtualChannelWrite(ch, (PCHAR)buf, (ULONG)len, &written);
    return ok && written == (ULONG)len;
}

static bool rdpdr_send_server_announce(HANDLE ch) {
    /* Header(4) + VersionMajor(2) + VersionMinor(2) + ClientId(4) */
    wStream *s = Stream_New(NULL, 12);
    if (!s) return false;
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_SERVER_ANNOUNCE);
    Stream_Write_UINT16(s, RDPDR_VERSION_MAJOR);
    Stream_Write_UINT16(s, RDPDR_VERSION_MINOR);
    Stream_Write_UINT32(s, 1);   /* initial ClientId = 1 */
    bool ok = rdpdr_write_pdu(ch, s);
    Stream_Free(s, TRUE);
    if (ok) rdp_verbose("rdpdr: -> SERVER_ANNOUNCE");
    return ok;
}

static bool rdpdr_send_caps_request(HANDLE ch) {
    /* Header(4) + numCaps(2) + pad(2) + one GeneralCap(44) = 52 bytes */
    wStream *s = Stream_New(NULL, 52);
    if (!s) return false;
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_CAPABILITY_REQUEST);
    Stream_Write_UINT16(s, 1);    /* numCapabilities */
    Stream_Write_UINT16(s, 0);    /* padding */
    /* General capability set (MS-RDPEFS §2.2.2.7.1) */
    Stream_Write_UINT16(s, CAP_GENERAL_TYPE);
    Stream_Write_UINT16(s, 44);   /* capabilityLength */
    Stream_Write_UINT32(s, 2);    /* version */
    Stream_Write_UINT32(s, 0);    /* osType */
    Stream_Write_UINT32(s, 0);    /* osVersion */
    Stream_Write_UINT16(s, RDPDR_VERSION_MAJOR);
    Stream_Write_UINT16(s, RDPDR_VERSION_MINOR);
    Stream_Write_UINT32(s, 0x00007fff); /* ioCode1 */
    Stream_Write_UINT32(s, 0);          /* ioCode2 */
    Stream_Write_UINT32(s, 0x0000000f); /* extendedPDU */
    Stream_Write_UINT32(s, 0);          /* extraFlags1 */
    Stream_Write_UINT32(s, 0);          /* extraFlags2 */
    Stream_Write_UINT32(s, 0);          /* specialTypeDeviceCap */
    bool ok = rdpdr_write_pdu(ch, s);
    Stream_Free(s, TRUE);
    if (ok) rdp_verbose("rdpdr: -> CAPABILITY_REQUEST (1 cap)");
    return ok;
}

static bool rdpdr_send_clientid_confirm(HANDLE ch, uint16_t clientId) {
    wStream *s = Stream_New(NULL, 12);
    if (!s) return false;
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_CLIENTID_CONFIRM);
    Stream_Write_UINT16(s, RDPDR_VERSION_MAJOR);
    Stream_Write_UINT16(s, RDPDR_VERSION_MINOR);
    Stream_Write_UINT32(s, (UINT32)clientId);
    bool ok = rdpdr_write_pdu(ch, s);
    Stream_Free(s, TRUE);
    if (ok) rdp_verbose("rdpdr: -> CLIENTID_CONFIRM (clientId=%u)", (unsigned)clientId);
    return ok;
}

static void rdpdr_send_device_reply(HANDLE ch, uint32_t deviceId, uint32_t result) {
    wStream *s = Stream_New(NULL, 12);
    if (!s) return;
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_DEVICE_REPLY);
    Stream_Write_UINT32(s, deviceId);
    Stream_Write_UINT32(s, result);
    rdpdr_write_pdu(ch, s);
    Stream_Free(s, TRUE);
}

/* Allocate the next monotonic IRP request id and store a pending entry.
 * cb may be NULL for fire-and-forget.  Returns 0 if the table is full. */
static uint32_t rdpdr_alloc_request(RDPPeerContext *ctx,
                                     uint32_t deviceId, const char *path,
                                     RDPIrpCallback cb, void *userdata) {
    for (int i = 0; i < RDPDR_MAX_PENDING; i++) {
        if (ctx->rdpdrPending[i].requestId == 0) {
            uint32_t rid = ++ctx->rdpdrNextReqId;
            if (rid == 0) rid = ++ctx->rdpdrNextReqId; /* skip id 0 (sentinel) */
            ctx->rdpdrPending[i].requestId = rid;
            ctx->rdpdrPending[i].deviceId  = deviceId;
            ctx->rdpdrPending[i].callback  = cb;
            ctx->rdpdrPending[i].userdata  = userdata;
            strncpy(ctx->rdpdrPending[i].path, path ? path : "",
                    sizeof(ctx->rdpdrPending[i].path) - 1);
            ctx->rdpdrPending[i].path[sizeof(ctx->rdpdrPending[i].path) - 1] = '\0';
            return rid;
        }
    }
    rdp_verbose("rdpdr: pending table full — dropping IRP for dev %u", deviceId);
    return 0;
}

/* Free a slot in the pending table by request id and invoke its callback.
 * payload/payloadLen are the bytes following the IOCOMPLETION fixed header.
 * Returns the device id associated with the request, or 0 if not found. */
static uint32_t rdpdr_free_request(RDPPeerContext *ctx, uint32_t requestId,
                                    uint32_t ioStatus,
                                    const uint8_t *payload, uint32_t payloadLen) {
    for (int i = 0; i < RDPDR_MAX_PENDING; i++) {
        if (ctx->rdpdrPending[i].requestId == requestId) {
            uint32_t       devId = ctx->rdpdrPending[i].deviceId;
            RDPIrpCallback cb    = ctx->rdpdrPending[i].callback;
            void          *ud    = ctx->rdpdrPending[i].userdata;
            rdp_verbose("rdpdr: IRP completion for requestId=%u dev=%u path=\"%s\"",
                        requestId, devId, ctx->rdpdrPending[i].path);
            ctx->rdpdrPending[i].requestId = 0;
            ctx->rdpdrPending[i].callback  = NULL;
            ctx->rdpdrPending[i].userdata  = NULL;
            /* Invoke callback AFTER zeroing the slot so re-entrant alloc is safe. */
            if (cb) cb(ioStatus, payload, payloadLen, ud);
            return devId;
        }
    }
    return 0;
}

/*
 * Send a DR_DRIVE_QUERY_INFORMATION_REQ to ask the client for the standard
 * file info (size + allocation) for the drive root. This is the simplest IRP
 * that gives us something useful (free space / total size) without requiring a
 * CREATE first. The server opens fileId=0 (root pseudo-handle) and asks for
 * RDPDR_FileStandardInformation. The client will respond with
 * PAKID_CORE_DEVICE_IOCOMPLETION carrying an IoStatus and the 24-byte
 * FILE_STANDARD_INFORMATION structure.
 *
 * MS-RDPEFS §2.2.3.3.9  DR_DRIVE_QUERY_INFORMATION_REQ
 * MS-RDPEFS §2.2.3.4.9  DR_DRIVE_QUERY_INFORMATION_RSP
 */
static bool rdpdr_send_query_info_req(RDPPeerContext *ctx, uint32_t deviceId) {
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, "\\", NULL, NULL);
    if (rid == 0) return false;

    /* Header(4) + DeviceId(4) + FileId(4) + CompletionId(4) +
     * MajorFunction(4) + MinorFunction(4) + Padding(20) = IRP header 44 bytes
     * + FsInformationClass(4) + Padding(4) = 52 bytes total */
    wStream *s = Stream_New(NULL, 52);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    /* Packet header */
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_DEVICE_IOREQUEST);

    /* DR_IRP_REQ — MS-RDPEFS §2.2.1.4 */
    Stream_Write_UINT32(s, deviceId);
    Stream_Write_UINT32(s, 0);          /* FileId = 0 (root) */
    Stream_Write_UINT32(s, rid);        /* CompletionId (our request id) */
    Stream_Write_UINT32(s, IRP_MJ_QUERY_INFORMATION);
    Stream_Write_UINT32(s, 0);          /* MinorFunction = 0 */
    /* 20 bytes of padding to complete the 40-byte IRP header body */
    Stream_Write_UINT32(s, 0);
    Stream_Write_UINT32(s, 0);
    Stream_Write_UINT32(s, 0);
    Stream_Write_UINT32(s, 0);
    Stream_Write_UINT32(s, 0);

    /* DR_DRIVE_QUERY_INFORMATION_REQ body */
    Stream_Write_UINT32(s, RDPDR_FileStandardInformation);
    Stream_Write_UINT32(s, 0); /* padding */

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (ok)
        rdp_verbose("rdpdr: -> QUERY_INFORMATION_REQ (dev=%u rid=%u "
                    "RDPDR_FileStandardInformation)", deviceId, rid);
    else
        rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    return ok;
}

/* ── IRP send helpers ─────────────────────────────────────────────────────
 *
 * Each helper builds the standard DR_IRP_REQ header (MS-RDPEFS §2.2.1.4):
 *   Packet header  : RDPDR_CTYP_CORE(2) + PAKID_CORE_DEVICE_IOREQUEST(2)
 *   IRP body header: DeviceId(4) + FileId(4) + CompletionId(4) +
 *                    MajorFunction(4) + MinorFunction(4) + Padding(20)
 * Total fixed header = 4 + 40 = 44 bytes before the specific body.
 *
 * ALL helpers must be called under xportLock.
 * cb may be NULL for fire-and-forget requests.
 */

/* Write the common 44-byte IRP header into stream s. */
static void rdpdr_write_irp_header(wStream *s, uint32_t deviceId,
                                    uint32_t fileId, uint32_t rid,
                                    uint32_t majorFn, uint32_t minorFn) {
    Stream_Write_UINT16(s, RDPDR_CTYP_CORE);
    Stream_Write_UINT16(s, PAKID_CORE_DEVICE_IOREQUEST);
    Stream_Write_UINT32(s, deviceId);
    Stream_Write_UINT32(s, fileId);
    Stream_Write_UINT32(s, rid);
    Stream_Write_UINT32(s, majorFn);
    Stream_Write_UINT32(s, minorFn);
    /* 20 bytes of padding (5 x uint32 = 0x00 filler per spec). */
    Stream_Write_UINT32(s, 0); Stream_Write_UINT32(s, 0);
    Stream_Write_UINT32(s, 0); Stream_Write_UINT32(s, 0);
    Stream_Write_UINT32(s, 0);
}

/* IRP_MJ_CREATE — open a file or directory.
 * path is UTF-8, no leading slash; internally converted to UTF-16LE. */
bool rdpdr_send_create_req(RDPPeerContext *ctx, uint32_t deviceId,
                            const char *path,
                            uint32_t desiredAccess,
                            uint32_t createDisposition,
                            uint32_t createOptions,
                            RDPIrpCallback cb, void *userdata) {
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, path, cb, userdata);
    if (rid == 0) return false;

    /* Convert path to UTF-16LE. */
    size_t pathLen = path ? strlen(path) : 0;
    /* Max path: 260 chars → 520 bytes UTF-16 + 2 for NUL. */
    uint16_t utf16[261];
    uint32_t utf16Len = 0;
    for (size_t i = 0; i < pathLen && i < 260; i++) {
        /* Simple ASCII->UTF-16LE (rdpdr paths are drive-relative ASCII). */
        utf16[utf16Len++] = (uint16_t)(unsigned char)path[i];
    }
    uint32_t pathBytes = utf16Len * 2; /* byte count sent on wire (no NUL) */

    /* DR_CREATE_REQ body (MS-RDPEFS §2.2.3.3.1):
     *   DesiredAccess(4) + AllocationSize(8) + FileAttributes(4) +
     *   ShareAccess(4) + CreateDisposition(4) + CreateOptions(4) +
     *   PathLength(4) + Path(PathLength) */
    size_t totalSize = 44 + 32 + pathBytes;
    wStream *s = Stream_New(NULL, totalSize);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, 0, rid, IRP_MJ_CREATE, 0);
    Stream_Write_UINT32(s, desiredAccess);
    Stream_Write_UINT64(s, 0);            /* AllocationSize = 0 */
    Stream_Write_UINT32(s, 0);            /* FileAttributes = normal */
    Stream_Write_UINT32(s, 3);            /* ShareAccess = read|write */
    Stream_Write_UINT32(s, createDisposition);
    Stream_Write_UINT32(s, createOptions);
    Stream_Write_UINT32(s, pathBytes);
    for (uint32_t i = 0; i < utf16Len; i++) Stream_Write_UINT16(s, utf16[i]);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> CREATE_REQ dev=%u rid=%u path=\"%s\"",
                     deviceId, rid, path ? path : "");
    return ok;
}

/* IRP_MJ_CLOSE — close a file handle. */
bool rdpdr_send_close_req(RDPPeerContext *ctx, uint32_t deviceId,
                           uint32_t fileId,
                           RDPIrpCallback cb, void *userdata) {
    char label[32];
    snprintf(label, sizeof(label), "close(%u)", fileId);
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_CLOSE_REQ body: just 32 bytes of padding after the IRP header. */
    wStream *s = Stream_New(NULL, 44 + 32);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid, IRP_MJ_CLOSE, 0);
    /* 32 bytes Padding */
    for (int i = 0; i < 8; i++) Stream_Write_UINT32(s, 0);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> CLOSE_REQ dev=%u fileId=%u rid=%u",
                     deviceId, fileId, rid);
    return ok;
}

/* IRP_MJ_READ — read bytes from an open file. */
bool rdpdr_send_read_req(RDPPeerContext *ctx, uint32_t deviceId,
                          uint32_t fileId, uint64_t offset, uint32_t length,
                          RDPIrpCallback cb, void *userdata) {
    char label[32];
    snprintf(label, sizeof(label), "read(%u)", fileId);
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_READ_REQ body (MS-RDPEFS §2.2.3.3.3):
     *   Length(4) + Offset(8) + Padding(20) */
    wStream *s = Stream_New(NULL, 44 + 32);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid, IRP_MJ_READ, 0);
    Stream_Write_UINT32(s, length);
    Stream_Write_UINT64(s, offset);
    /* Padding: 20 bytes (5 x uint32) */
    for (int i = 0; i < 5; i++) Stream_Write_UINT32(s, 0);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> READ_REQ dev=%u fileId=%u off=%llu len=%u rid=%u",
                     deviceId, fileId, (unsigned long long)offset, length, rid);
    return ok;
}

/* IRP_MJ_WRITE — write bytes to an open file. */
bool rdpdr_send_write_req(RDPPeerContext *ctx, uint32_t deviceId,
                           uint32_t fileId, uint64_t offset,
                           const uint8_t *data, uint32_t length,
                           RDPIrpCallback cb, void *userdata) {
    char label[32];
    snprintf(label, sizeof(label), "write(%u)", fileId);
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_WRITE_REQ body (MS-RDPEFS §2.2.3.3.4):
     *   Length(4) + Offset(8) + Padding(20) + WriteData(Length) */
    wStream *s = Stream_New(NULL, 44 + 32 + length);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid, IRP_MJ_WRITE, 0);
    Stream_Write_UINT32(s, length);
    Stream_Write_UINT64(s, offset);
    for (int i = 0; i < 5; i++) Stream_Write_UINT32(s, 0); /* padding */
    if (length > 0 && data) Stream_Write(s, data, length);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> WRITE_REQ dev=%u fileId=%u off=%llu len=%u rid=%u",
                     deviceId, fileId, (unsigned long long)offset, length, rid);
    return ok;
}

/* IRP_MJ_DIRECTORY_CONTROL / IRP_MN_QUERY_DIRECTORY — list a directory.
 * pattern is the search pattern (e.g. "*"); informationClass is
 * FileFullDirectoryInformation (2). */
bool rdpdr_send_query_dir_req(RDPPeerContext *ctx, uint32_t deviceId,
                               uint32_t fileId, const char *pattern,
                               RDPIrpCallback cb, void *userdata) {
    char label[64];
    snprintf(label, sizeof(label), "querydir(%u,%s)", fileId,
             pattern ? pattern : "*");
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* Convert pattern to UTF-16LE */
    const char *pat = pattern ? pattern : "*";
    size_t patLen = strlen(pat);
    uint16_t utf16[261];
    uint32_t utf16Len = 0;
    for (size_t i = 0; i < patLen && i < 260; i++)
        utf16[utf16Len++] = (uint16_t)(unsigned char)pat[i];
    uint32_t patBytes = utf16Len * 2;

    /* DR_DRIVE_QUERY_DIRECTORY_REQ (MS-RDPEFS §2.2.3.3.10):
     *   FsInformationClass(4) + InitialQuery(1) + PathLength(4) + Padding(23) + Path */
    size_t bodySize = 4 + 1 + 4 + 23 + patBytes;
    wStream *s = Stream_New(NULL, 44 + bodySize);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid,
                            IRP_MJ_DIRECTORY_CONTROL, IRP_MN_QUERY_DIRECTORY);
    Stream_Write_UINT32(s, RDPDR_FileFullDirectoryInformation);
    Stream_Write_UINT8(s,  1);           /* InitialQuery = 1 (restart scan) */
    Stream_Write_UINT32(s, patBytes);
    /* 23 bytes padding */
    for (int i = 0; i < 5; i++) Stream_Write_UINT32(s, 0);
    Stream_Write_UINT8(s, 0);            /* last padding byte */
    /* Path */
    for (uint32_t i = 0; i < utf16Len; i++) Stream_Write_UINT16(s, utf16[i]);

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> QUERY_DIR_REQ dev=%u fileId=%u pat=\"%s\" rid=%u",
                     deviceId, fileId, pat, rid);
    return ok;
}

/* IRP_MJ_SET_INFORMATION (FileDispositionInformation) — mark file for deletion. */
bool rdpdr_send_delete_req(RDPPeerContext *ctx, uint32_t deviceId,
                            uint32_t fileId,
                            RDPIrpCallback cb, void *userdata) {
    char label[32];
    snprintf(label, sizeof(label), "delete(%u)", fileId);
    uint32_t rid = rdpdr_alloc_request(ctx, deviceId, label, cb, userdata);
    if (rid == 0) return false;

    /* DR_SET_INFORMATION_REQ body (MS-RDPEFS §2.2.3.3.9):
     *   FsInformationClass(4) + Length(4) + Padding(24) + SetBuffer(Length)
     * FileDispositionInformation body: DeleteFile(1) = 1. */
    wStream *s = Stream_New(NULL, 44 + 4 + 4 + 24 + 1);
    if (!s) { rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0); return false; }

    rdpdr_write_irp_header(s, deviceId, fileId, rid, IRP_MJ_SET_INFORMATION, 0);
    Stream_Write_UINT32(s, RDPDR_FileDispositionInformation);
    Stream_Write_UINT32(s, 1);   /* Length of SetBuffer = 1 byte */
    for (int i = 0; i < 6; i++) Stream_Write_UINT32(s, 0); /* 24 bytes padding */
    Stream_Write_UINT8(s,  1);   /* DeleteFile = TRUE */

    bool ok = rdpdr_write_pdu(ctx->rdpdrChannel, s);
    Stream_Free(s, TRUE);
    if (!ok) rdpdr_free_request(ctx, rid, 0xC0000000, NULL, 0);
    else rdp_verbose("rdpdr: -> DELETE_REQ dev=%u fileId=%u rid=%u",
                     deviceId, fileId, rid);
    return ok;
}

/* Decode one PDU from the rdpdr channel and advance the state machine. */
static void rdpdr_handle_pdu(RDPPeerContext *ctx, BYTE *buf, ULONG len) {
    wStream stack; /* stack-allocated reader; avoids heap alloc for each PDU */
    wStream *s = Stream_StaticInit(&stack, buf, (size_t)len);

    if (Stream_GetRemainingLength(s) < 4) return;
    UINT16 component, packetId;
    Stream_Read_UINT16(s, component);
    Stream_Read_UINT16(s, packetId);
    if (component != RDPDR_CTYP_CORE) {
        rdp_verbose("rdpdr: unknown component 0x%04x", component);
        return;
    }

    switch (packetId) {

    case PAKID_CORE_CLIENT_ANNOUNCE_REPLY: {
        if (Stream_GetRemainingLength(s) < 8) break;
        UINT16 maj, min; UINT32 cid;
        Stream_Read_UINT16(s, maj);
        Stream_Read_UINT16(s, min);
        Stream_Read_UINT32(s, cid);
        ctx->rdpdrClientId = (uint16_t)(cid & 0xFFFF);
        rdp_verbose("rdpdr: <- CLIENT_ANNOUNCE_REPLY v%u.%u clientId=%u",
                    (unsigned)maj, (unsigned)min, (unsigned)ctx->rdpdrClientId);
        break;
    }

    case PAKID_CORE_CLIENT_NAME: {
        if (Stream_GetRemainingLength(s) < 12) break;
        UINT32 unicodeFlag, codePage, nameLen;
        Stream_Read_UINT32(s, unicodeFlag);
        Stream_Read_UINT32(s, codePage);
        Stream_Read_UINT32(s, nameLen);
        (void)codePage;
        char name[128] = "(empty)";
        if (nameLen > 0 && (size_t)nameLen <= Stream_GetRemainingLength(s)) {
            if (unicodeFlag && nameLen >= 2) {
                size_t chars = (nameLen / 2 < 127) ? nameLen / 2 : 127;
                for (size_t i = 0; i < chars; i++) {
                    UINT16 wc; Stream_Read_UINT16(s, wc);
                    name[i] = (wc && wc < 128) ? (char)wc : '?';
                    if (!wc) { name[i] = '\0'; break; }
                }
                name[chars] = '\0';
            } else {
                size_t n = (nameLen < 127) ? nameLen : 127;
                Stream_Read(s, name, n);
                name[n] = '\0';
            }
        }
        rdp_verbose("rdpdr: <- CLIENT_NAME \"%s\"", name);

        /* Both ANNOUNCE_REPLY and NAME received — send caps + confirm. */
        if (ctx->rdpdrState == kRdpdrSentAnnounce) {
            if (rdpdr_send_caps_request(ctx->rdpdrChannel) &&
                rdpdr_send_clientid_confirm(ctx->rdpdrChannel, ctx->rdpdrClientId)) {
                ctx->rdpdrState = kRdpdrReceivedName;
            } else {
                ctx->rdpdrState = kRdpdrError;
                rdp_error("rdpdr: failed to send caps/confirm");
            }
        }
        break;
    }

    case PAKID_CORE_CAPABILITY_RESPONSE: {
        if (Stream_GetRemainingLength(s) < 4) break;
        UINT16 numCaps, pad;
        Stream_Read_UINT16(s, numCaps);
        Stream_Read_UINT16(s, pad);
        (void)pad;
        rdp_verbose("rdpdr: <- CAPABILITY_RESPONSE (%u caps)", (unsigned)numCaps);
        /* We accept whatever the client advertises; no negotiation needed for
         * enumeration-only mode. Stay in ReceivedName until device list arrives. */
        break;
    }

    case PAKID_CORE_DEVICE_LIST_ANNOUNCE: {
        if (Stream_GetRemainingLength(s) < 4) break;
        UINT32 deviceCount;
        Stream_Read_UINT32(s, deviceCount);
        rdp_info("rdpdr: <- DEVICE_LIST_ANNOUNCE — %u device(s)", (unsigned)deviceCount);

        /* Track how many drive slots we have filled so we can index webdavServers. */
        int driveSlot = 0;

        for (UINT32 i = 0; i < deviceCount; i++) {
            if (Stream_GetRemainingLength(s) < 20) break;
            UINT32 devType, devId, dataLen;
            char dosName[9] = {0};
            Stream_Read_UINT32(s, devType);
            Stream_Read_UINT32(s, devId);
            Stream_Read(s, dosName, 8);
            dosName[8] = '\0';
            Stream_Read_UINT32(s, dataLen);
            if (dataLen > 0 && (size_t)dataLen <= Stream_GetRemainingLength(s))
                Stream_Seek(s, (size_t)dataLen);

            const char *typeName = "unknown";
            switch (devType) {
                case RDPDR_DTYP_FILESYSTEM: typeName = "drive";     break;
                case RDPDR_DTYP_PRINT:      typeName = "printer";   break;
                case RDPDR_DTYP_SERIAL:     typeName = "serial";    break;
                case RDPDR_DTYP_PARALLEL:   typeName = "parallel";  break;
                case RDPDR_DTYP_SMARTCARD:  typeName = "smartcard"; break;
            }

            if (devType == RDPDR_DTYP_FILESYSTEM) {
                rdp_info("rdpdr: client drive #%u — id=%u name=\"%s\" "
                         "(starting embedded WebDAV server for Finder mount)",
                         (unsigned)i, (unsigned)devId, dosName);

                /* Desktop placeholder for immediate user feedback. */
                rdp_drive_mount_placeholder(dosName, devId);

                /* Start an embedded WebDAV server and mount via mount_webdav. */
                if (driveSlot < RDPDR_MAX_DEVICES) {
                    /* Ports 8760..8767 — one per drive slot. */
                    uint16_t port = (uint16_t)(8760 + (driveSlot % 100));
                    /* Must release xportLock before calling server_create which
                     * calls pthread_create and may need to call back into IRPs.
                     * ctx->base.peer is the owning freerdp_peer pointer. */
                    freerdp_peer *peerPtr = ctx->base.peer;
                    pthread_mutex_unlock(&ctx->xportLock);
                    RDPWebDAVServer *srv =
                        rdp_webdav_server_create(peerPtr, devId, dosName, port);
                    pthread_mutex_lock(&ctx->xportLock);

                    if (srv) {
                        ctx->webdavServers[driveSlot] = srv;
                        rdp_webdav_mount(srv);
                        rdp_info("rdpdr: WebDAV server started on port %u for drive \"%s\"",
                                 (unsigned)port, dosName);
                    } else {
                        rdp_error("rdpdr: failed to start WebDAV server for drive \"%s\"",
                                  dosName);
                    }
                    driveSlot++;
                } else {
                    rdp_verbose("rdpdr: no free WebDAV server slots for drive \"%s\"",
                                dosName);
                }

                /* Fire-and-forget probe to log drive capacity. */
                rdpdr_send_query_info_req(ctx, devId);
            } else {
                rdp_verbose("rdpdr: client device #%u — id=%u name=\"%s\" type=%s (not a drive)",
                            (unsigned)i, (unsigned)devId, dosName, typeName);
            }

            /* ACK every device with RDPDR_STATUS_SUCCESS so the client knows we saw it. */
            rdpdr_send_device_reply(ctx->rdpdrChannel, devId, RDPDR_STATUS_SUCCESS);
        }

        ctx->rdpdrState = kRdpdrReady;
        rdp_info("rdpdr: device enumeration complete — handshake done");
        break;
    }

    /* ── IRP I/O Completion (client -> server) ───────────────────────────── */
    case PAKID_CORE_DEVICE_IOCOMPLETION: {
        /* MS-RDPEFS §2.2.1.5  DR_DEVICE_IOCOMPLETION
         * Header(4 already consumed) + DeviceId(4) + CompletionId(4) +
         * IoStatus(4) = 12 more bytes before the payload. */
        if (Stream_GetRemainingLength(s) < 12) {
            rdp_verbose("rdpdr: IOCOMPLETION too short (%zu bytes remaining)",
                        Stream_GetRemainingLength(s));
            break;
        }
        UINT32 devId, completionId, ioStatus;
        Stream_Read_UINT32(s, devId);
        Stream_Read_UINT32(s, completionId);
        Stream_Read_UINT32(s, ioStatus);

        /* Grab the payload bytes before we call rdpdr_free_request (which invokes
         * the callback that might use them).  The stream is stack-allocated over
         * the original read buffer, so the pointer is valid during this call. */
        const uint8_t *payload    = Stream_Pointer(s);
        uint32_t       payloadLen = (uint32_t)Stream_GetRemainingLength(s);

        /* Look up the pending request, invoke its callback, and free the slot. */
        uint32_t matchedDev = rdpdr_free_request(ctx, completionId,
                                                  ioStatus, payload, payloadLen);
        if (matchedDev == 0) {
            /* Could be an unsolicited completion for a request we didn't send
             * (e.g. the client proactively sending info). Log and ignore. */
            rdp_verbose("rdpdr: <- IOCOMPLETION dev=%u cid=%u status=0x%08x "
                        "(no matching pending request)",
                        devId, completionId, ioStatus);
            break;
        }

        rdp_verbose("rdpdr: IOCOMPLETION dev=%u cid=%u status=0x%08x payload=%u bytes",
                    devId, completionId, ioStatus, payloadLen);
        break;
    }

    default:
        rdp_verbose("rdpdr: unhandled packetId=0x%04x in state=%d", packetId, ctx->rdpdrState);
        break;
    }
}

/*
 * Open the "rdpdr" static virtual channel. Called from peer_post_connect when
 * RDP_RDPDR_ENABLED=1. Returns true if the channel opened and SERVER_ANNOUNCE
 * was sent successfully.
 */
bool rdp_peer_open_rdpdr(freerdp_peer *peer) {
    const char *env = getenv("RDP_RDPDR_ENABLED");
    if (!env || strcmp(env, "1") != 0) {
        rdp_verbose("rdpdr: disabled (RDP_RDPDR_ENABLED != 1)");
        return false;
    }

    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->vcm || ctx->vcm == INVALID_HANDLE_VALUE) {
        rdp_error("rdpdr: VCM not open");
        return false;
    }

    /* Open as a STATIC virtual channel. rdpdr is always static (not drdynvc). */
    ctx->rdpdrChannel = WTSVirtualChannelOpen(ctx->vcm,
                                               WTS_CURRENT_SESSION,
                                               (LPSTR)"rdpdr");
    if (!ctx->rdpdrChannel || ctx->rdpdrChannel == INVALID_HANDLE_VALUE) {
        ctx->rdpdrChannel = NULL;
        rdp_verbose("rdpdr: WTSVirtualChannelOpen failed — "
                    "client may not have advertised the channel");
        return false;
    }

    /* Retrieve the channel's event handle for the run-loop WaitForMultipleObjects. */
    void   *evPtr = NULL;
    ULONG   evLen = sizeof(evPtr);
    if (WTSVirtualChannelQuery(ctx->rdpdrChannel,
                               WTSVirtualEventHandle, &evPtr, &evLen) && evPtr) {
        ctx->rdpdrEvent = (HANDLE)*(void **)evPtr;
        WTSFreeMemory(evPtr);
    }

    ctx->rdpdrState    = kRdpdrSentAnnounce;
    ctx->rdpdrClientId = 0;

    /* Send the first handshake PDU under xportLock. */
    pthread_mutex_lock(&ctx->xportLock);
    bool ok = rdpdr_send_server_announce(ctx->rdpdrChannel);
    pthread_mutex_unlock(&ctx->xportLock);

    if (!ok) {
        rdp_error("rdpdr: SERVER_ANNOUNCE write failed");
        WTSVirtualChannelClose(ctx->rdpdrChannel);
        ctx->rdpdrChannel = NULL;
        ctx->rdpdrEvent   = NULL;
        ctx->rdpdrState   = kRdpdrError;
        return false;
    }

    rdp_info("rdpdr: channel open and SERVER_ANNOUNCE sent");
    return true;
}

/* Maximum PDU size for a static virtual channel. The RDP spec limits static
 * VC PDUs to CHANNEL_CHUNK_LENGTH (1600) per write, and rdpdr PDUs are
 * small (handshake packets < 100 bytes; device list < 512 bytes). 4096
 * gives comfortable headroom for a list of many devices. */
#define RDPDR_READ_BUF_SIZE 4096

/*
 * Drain all pending inbound PDUs from the rdpdr channel and advance the
 * MS-RDPEFS handshake state machine. Called from the peer run loop under
 * xportLock whenever the rdpdr event handle fires.
 */
void rdp_peer_pump_rdpdr(freerdp_peer *peer) {
    RDPPeerContext *ctx = (RDPPeerContext *)peer->context;
    if (!ctx->rdpdrChannel || ctx->rdpdrState == kRdpdrError) return;

    /* WTSVirtualChannelRead(handle, timeout_ms, buf, bufSize, &bytesRead).
     * timeout=0 → non-blocking; returns FALSE when no data is pending. */
    BYTE  buf[RDPDR_READ_BUF_SIZE];
    ULONG bytesRead = 0;
    while (WTSVirtualChannelRead(ctx->rdpdrChannel, 0,
                                  (PCHAR)buf, (ULONG)sizeof(buf), &bytesRead)
           && bytesRead > 0) {
        rdpdr_handle_pdu(ctx, buf, bytesRead);
        bytesRead = 0;
    }
}
