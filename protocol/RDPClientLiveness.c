#include "protocol/RDPClientLiveness.h"

static bool frame_after(uint32_t lhs, uint32_t rhs) {
    return (int32_t)(lhs - rhs) > 0;
}
bool rdp_client_liveness_timed_out(
        const RDPClientLivenessSnapshot *snapshot,
        uint64_t nowMS,
        uint32_t timeoutMS) {
    if (!snapshot || timeoutMS == 0u || !snapshot->activated ||
        !snapshot->gfxReady)
        return false;

    /* Windows App on iPad can send Suppress Output when entering the
     * background, then fail to send the corresponding allow PDU after iPadOS
     * resumes it. No frames are sent while suppressed, so an outstanding-frame
     * watchdog can never detect this frozen-last-frame state. Bound the pause
     * explicitly so the retained desktop can be adopted by a fresh transport. */
    if (snapshot->outputSuppressed) {
        return snapshot->suppressedSinceMS != 0u &&
               nowMS >= snapshot->suppressedSinceMS &&
               nowMS - snapshot->suppressedSinceMS >= timeoutMS;
    }

    if (!snapshot->feedbackSeen || snapshot->lastResponseMS == 0u ||
        nowMS < snapshot->lastResponseMS)
        return false;

    uint32_t confirmed = snapshot->ackFrameId;
    if (frame_after(snapshot->qoeFrameId, confirmed))
        confirmed = snapshot->qoeFrameId;
    if (!frame_after(snapshot->sentFrameId, confirmed))
        return false;

    /* A client may legitimately omit the final FrameAcknowledge while still
     * returning QoE for every subsequent heartbeat. One outstanding frame is
     * therefore not evidence of a dead renderer. A backgrounded client that
     * stopped responding accumulates heartbeat frames and still crosses this
     * threshold quickly. */
    if ((uint32_t)(snapshot->sentFrameId - confirmed) < 2u)
        return false;

    return nowMS - snapshot->lastResponseMS >= timeoutMS;
}

bool rdp_client_liveness_suppressed_probe_due(
        const RDPClientLivenessSnapshot *snapshot,
        uint64_t nowMS,
        uint32_t probeDelayMS) {
    return snapshot && probeDelayMS > 0u && snapshot->activated &&
           snapshot->gfxReady && snapshot->outputSuppressed &&
           snapshot->suppressedSinceMS != 0u &&
           nowMS >= snapshot->suppressedSinceMS &&
           nowMS - snapshot->suppressedSinceMS >= probeDelayMS;
}

bool rdp_client_liveness_surface_resync_due(
        bool compatibilityProbeAttempted,
        uint64_t pausedMS,
        uint64_t responseSilenceMS,
        uint32_t pauseThresholdMS,
        uint32_t silenceThresholdMS) {
    if (compatibilityProbeAttempted) return true;
    if (pauseThresholdMS > 0u && pausedMS >= pauseThresholdMS) return true;
    return silenceThresholdMS > 0u &&
           responseSilenceMS >= silenceThresholdMS;
}
