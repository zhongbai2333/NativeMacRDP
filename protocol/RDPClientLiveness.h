#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool activated;
    bool gfxReady;
    bool outputSuppressed;
    bool feedbackSeen;
    uint32_t sentFrameId;
    uint32_t ackFrameId;
    uint32_t qoeFrameId;
    uint64_t lastResponseMS;
    uint64_t suppressedSinceMS;
} RDPClientLivenessSnapshot;

/* True for either a previously responsive client with unacknowledged graphics
 * and no feedback, or an output-suppressed client that never sends the matching
 * restore signal. Static-but-healthy foreground clients are never expired. */
bool rdp_client_liveness_timed_out(
    const RDPClientLivenessSnapshot *snapshot,
    uint64_t nowMS,
    uint32_t timeoutMS);

/* A short, bounded compatibility probe for clients that suppress output on
 * backgrounding but omit both the allow and Refresh Rect PDUs on restore. */
bool rdp_client_liveness_suppressed_probe_due(
    const RDPClientLivenessSnapshot *snapshot,
    uint64_t nowMS,
    uint32_t probeDelayMS);

/* A client-side compositor can discard its mapped RDPGFX surface while a
 * mobile app is backgrounded. Recreate only the graphics surface after a
 * compatibility probe, a meaningful output pause, or a matching period with
 * no client feedback. The retained desktop itself is not affected. */
bool rdp_client_liveness_surface_resync_due(
    bool compatibilityProbeAttempted,
    uint64_t pausedMS,
    uint64_t responseSilenceMS,
    uint32_t pauseThresholdMS,
    uint32_t silenceThresholdMS);
