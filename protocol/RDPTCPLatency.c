#include "protocol/RDPTCPLatency.h"

#include <limits.h>
#include <stddef.h>

#define RDP_TCP_PACING_PERCENT             75u
#define RDP_TCP_MIN_INFLIGHT_FRAMES         3u
#define RDP_TCP_MAX_INFLIGHT_FRAMES         4u
#define RDP_TCP_FEEDBACK_WARMUP_SAMPLES    30u
#define RDP_TCP_CONGESTED_SAMPLES           3u
#define RDP_TCP_LARGE_CONFIRM_SAMPLES       8u
#define RDP_TCP_RATE_CHANGE_MIN_MS        1500u
#define RDP_TCP_RECOVERY_MIN_MS           2000u
#define RDP_TCP_RECOVERY_STABLE_SAMPLES    60u
#define RDP_TCP_UPWARD_PROBE_MIN_MS       10000u
#define RDP_TCP_UPWARD_PROBE_PERCENT        25u
#define RDP_TCP_UPWARD_PROBE_MIN_STEP   125000u
#define RDP_TCP_MIN_INFLIGHT_BYTES      131072u
#define RDP_TCP_MAX_INFLIGHT_BYTES     1048576u
#define RDP_TCP_MIN_CONGESTION_BYTES      8192u
#define RDP_TCP_MAX_CONGESTION_BYTES     32768u
#define RDP_UDP_MIN_HIGH_RTT_MS             80u
#define RDP_UDP_QUEUE_CONGESTION_BYTES  131072u
#define RDP_UDP_MIN_SATURATION_PACKETS       32u

static uint32_t clamp_u32(uint64_t value, uint32_t low, uint32_t high) {
    if (value < low) return low;
    if (value > high) return high;
    return (uint32_t)value;
}

static uint32_t calculate_inflight(const RDPTCPLatencyController *controller) {
    if (controller->explicitMaxInflightFrames)
        return controller->explicitMaxInflightFrames;
    if (!controller->baseRTTMS || !controller->frameIntervalMS)
        return RDP_TCP_MAX_INFLIGHT_FRAMES;

    /* One RTT of frames keeps the pipe occupied; one extra frame covers client
     * decode jitter. Capping at four prevents throughput seeking from turning
     * into a visible queue of old desktops on a high-latency TCP path. */
    uint64_t frames =
        ((uint64_t)controller->baseRTTMS + controller->frameIntervalMS - 1u) /
        controller->frameIntervalMS;
    frames += 1u;
    return clamp_u32(frames, RDP_TCP_MIN_INFLIGHT_FRAMES,
                     RDP_TCP_MAX_INFLIGHT_FRAMES);
}

void rdp_tcp_latency_init(RDPTCPLatencyController *controller,
                          uint32_t minimumBytesPerSec,
                          uint32_t configuredCeilingBytesPerSec,
                          uint32_t explicitMaxInflightFrames) {
    if (!controller) return;
    *controller = (RDPTCPLatencyController){0};
    if (!minimumBytesPerSec) minimumBytesPerSec = 1u;
    if (configuredCeilingBytesPerSec < minimumBytesPerSec)
        configuredCeilingBytesPerSec = minimumBytesPerSec;
    controller->minimumBytesPerSec = minimumBytesPerSec;
    controller->configuredCeilingBytesPerSec = configuredCeilingBytesPerSec;
    controller->measuredCeilingBytesPerSec = configuredCeilingBytesPerSec;
    controller->confirmedCeilingBytesPerSec = configuredCeilingBytesPerSec;
    controller->currentBytesPerSec = configuredCeilingBytesPerSec;
    controller->explicitMaxInflightFrames = explicitMaxInflightFrames;
    controller->maxInflightFrames = calculate_inflight(controller);
}

uint32_t rdp_tcp_latency_apply_network(RDPTCPLatencyController *controller,
                                       uint32_t bandwidthKbit,
                                       uint32_t baseRTTMS,
                                       uint64_t nowMS) {
    if (!controller) return 0;
    controller->baseRTTMS = baseRTTMS;
    controller->maxInflightFrames = calculate_inflight(controller);
    if (!bandwidthKbit) return controller->currentBytesPerSec;

    uint64_t measured = (uint64_t)bandwidthKbit * 1000u / 8u;
    measured = measured * RDP_TCP_PACING_PERCENT / 100u;
    const uint32_t target = clamp_u32(
        measured, controller->minimumBytesPerSec,
        controller->configuredCeilingBytesPerSec);
    controller->measuredCeilingBytesPerSec = target;
    controller->confirmedCeilingBytesPerSec = target;
    controller->currentBytesPerSec = target;
    controller->stableFeedbackCount = 0;
    controller->stableLargeFeedbackCount = 0;
    controller->lastRateChangeMS = nowMS;
    controller->lastUpwardProbeMS = nowMS;
    return target;
}

uint32_t rdp_tcp_latency_set_frame_interval(
    RDPTCPLatencyController *controller, uint32_t frameIntervalMS) {
    if (!controller) return 0;
    controller->frameIntervalMS = frameIntervalMS ? frameIntervalMS : 1u;
    controller->maxInflightFrames = calculate_inflight(controller);
    return controller->maxInflightFrames;
}

uint32_t rdp_tcp_latency_payload_inflight(uint32_t normalInflightFrames,
                                          uint32_t targetBytesPerSec,
                                          uint32_t lastFrameBytes) {
    uint32_t largeFrameBytes = targetBytesPerSec / 20u; /* 50 ms of payload */
    if (largeFrameBytes < 65536u) largeFrameBytes = 65536u;
    if (largeFrameBytes > 262144u) largeFrameBytes = 262144u;
    if (lastFrameBytes >= largeFrameBytes && normalInflightFrames > 2u)
        return 2u;
    return normalInflightFrames;
}

uint32_t rdp_tcp_latency_inflight_budget(uint32_t targetBytesPerSec,
                                         uint32_t baseRTTMS,
                                         uint32_t smoothedFeedbackMS) {
    uint32_t latencyMS = baseRTTMS ? baseRTTMS : smoothedFeedbackMS;
    if (latencyMS < 40u) latencyMS = 40u;
    if (latencyMS > 250u) latencyMS = 250u;

    uint32_t windowMS = latencyMS * 2u;
    if (windowMS < 100u) windowMS = 100u;
    if (windowMS > 500u) windowMS = 500u;
    const uint64_t bytes = ((uint64_t)targetBytesPerSec * windowMS + 999u) /
                           1000u;
    return clamp_u32(bytes, RDP_TCP_MIN_INFLIGHT_BYTES,
                     RDP_TCP_MAX_INFLIGHT_BYTES);
}

uint32_t rdp_tcp_latency_qoe_frame_limit(uint32_t explicitLimit,
                                         uint64_t inflightBytes,
                                         uint32_t inflightBudgetBytes) {
    if (explicitLimit) return explicitLimit;
    if (!inflightBudgetBytes) return 8u;

    uint32_t tinyBytes = inflightBudgetBytes / 8u;
    if (tinyBytes < 16384u) tinyBytes = 16384u;
    if (tinyBytes > 32768u) tinyBytes = 32768u;
    if (inflightBytes <= tinyBytes) return 32u;

    uint32_t modestBytes = inflightBudgetBytes / 3u;
    if (modestBytes < 65536u) modestBytes = 65536u;
    if (modestBytes > 262144u) modestBytes = 262144u;
    if (inflightBytes <= modestBytes) return 16u;
    return 8u;
}

uint32_t rdp_tcp_latency_latest_feedback_frame(uint32_t qoeFrame,
                                               uint32_t frameAck,
                                               bool frameAckSeen) {
    if (!frameAckSeen) return qoeFrame;
    return (int32_t)(frameAck - qoeFrame) > 0 ? frameAck : qoeFrame;
}

static RDPTCPLatencyAdjustment reduce_rate(
    RDPTCPLatencyController *controller, uint64_t nowMS, uint32_t percent,
    RDPTCPLatencyCause cause) {
    if (nowMS - controller->lastRateChangeMS < RDP_TCP_RATE_CHANGE_MIN_MS)
        return RDPTCPLatencyUnchanged;
    uint32_t reduced = (uint32_t)((uint64_t)controller->currentBytesPerSec *
                                  percent / 100u);
    if (reduced < controller->minimumBytesPerSec)
        reduced = controller->minimumBytesPerSec;
    /* A speculative upward probe is never allowed to drag its new ceiling
     * through repeated recovery cycles. The first real congestion signal drops
     * straight back to the last large-frame-confirmed rate. Congestion at an
     * already-confirmed rate means the link itself worsened, so lower the
     * confirmed ceiling too and allow adaptation all the way to the configured
     * floor. */
    if (controller->currentBytesPerSec >
        controller->confirmedCeilingBytesPerSec) {
        if (reduced > controller->confirmedCeilingBytesPerSec)
            reduced = controller->confirmedCeilingBytesPerSec;
    } else {
        controller->confirmedCeilingBytesPerSec = reduced;
    }
    controller->stableFeedbackCount = 0;
    controller->stableLargeFeedbackCount = 0;
    if (reduced >= controller->currentBytesPerSec)
        return RDPTCPLatencyUnchanged;
    controller->currentBytesPerSec = reduced;
    controller->measuredCeilingBytesPerSec = reduced;
    controller->lastAdjustmentCause = cause;
    controller->lastRateChangeMS = nowMS;
    controller->lastUpwardProbeMS = nowMS;
    return RDPTCPLatencyReduced;
}

RDPTCPLatencyAdjustment rdp_tcp_latency_on_feedback(
    RDPTCPLatencyController *controller,
    uint32_t feedbackElapsedMS,
    uint32_t frameBytes,
    uint32_t clientDecodeMS,
    uint32_t clientRenderMS,
    uint64_t feedbackCount,
    uint64_t nowMS) {
    return rdp_tcp_latency_on_feedback_with_transport(
        controller, feedbackElapsedMS, frameBytes, clientDecodeMS,
        clientRenderMS, NULL, feedbackCount, nowMS);
}

static bool reliable_udp_congested(
    const RDPTCPLatencyController *controller,
    const RDPTransportFeedback *transport) {
    if (!controller || !transport || !transport->reliableUDPActive ||
        !transport->sampleFresh)
        return false;
    if (transport->recentLossOrRetransmit ||
        transport->queuedBytes >= RDP_UDP_QUEUE_CONGESTION_BYTES)
        return true;

    uint32_t highRTTMS = controller->baseRTTMS * 4u;
    if (highRTTMS < RDP_UDP_MIN_HIGH_RTT_MS)
        highRTTMS = RDP_UDP_MIN_HIGH_RTT_MS;
    if (transport->smoothedRTTMS > highRTTMS)
        return true;

    return transport->congestionWindowPackets > 0u &&
           transport->inflightPackets >= RDP_UDP_MIN_SATURATION_PACKETS &&
           (uint64_t)transport->inflightPackets * 4u >=
               (uint64_t)transport->congestionWindowPackets * 3u;
}

bool rdp_tcp_latency_transport_healthy(
    const RDPTCPLatencyController *controller,
    const RDPTransportFeedback *transport) {
    return controller && transport && transport->reliableUDPActive &&
           transport->sampleFresh &&
           !reliable_udp_congested(controller, transport);
}

RDPTCPLatencyAdjustment rdp_tcp_latency_on_feedback_with_transport(
    RDPTCPLatencyController *controller,
    uint32_t feedbackElapsedMS,
    uint32_t frameBytes,
    uint32_t clientDecodeMS,
    uint32_t clientRenderMS,
    const RDPTransportFeedback *transport,
    uint64_t feedbackCount,
    uint64_t nowMS) {
    if (!controller || !feedbackElapsedMS)
        return RDPTCPLatencyUnchanged;

    controller->lastAdjustmentCause = RDPTCPLatencyCauseNone;

    if (!controller->smoothedFeedbackMS)
        controller->smoothedFeedbackMS = feedbackElapsedMS;
    else
        controller->smoothedFeedbackMS =
            (controller->smoothedFeedbackMS * 7u + feedbackElapsedMS) / 8u;

    /* Do not treat first-paint/display creation as congestion. Windows App can
     * hold the first QoE acknowledgement for seconds while constructing its
     * renderer even on a healthy transport. */
    if (feedbackCount < RDP_TCP_FEEDBACK_WARMUP_SAMPLES)
        return RDPTCPLatencyUnchanged;

    /* A full-screen Progressive frame is commonly 200-350 KiB. Its healthy
     * serialization time is already 100-200 ms on this WAN path, so treating
     * raw feedback elapsed time as queueing caused the controller to collapse
     * from 15 Mbit/s to 2 Mbit/s precisely during large desktop motion. Add the
     * expected serialization time before judging congestion. */
    uint32_t serializationMS = 0u;
    if (frameBytes && controller->measuredCeilingBytesPerSec) {
        const uint64_t value =
            ((uint64_t)frameBytes * 1000u +
             controller->measuredCeilingBytesPerSec - 1u) /
            controller->measuredCeilingBytesPerSec;
        serializationMS = value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
    }
    uint32_t congestedThreshold = controller->baseRTTMS * 4u;
    if (congestedThreshold < 200u) congestedThreshold = 200u;
    uint32_t stableThreshold = controller->baseRTTMS * 3u;
    if (stableThreshold < 140u) stableThreshold = 140u;
    if (UINT32_MAX - congestedThreshold < serializationMS)
        congestedThreshold = UINT32_MAX;
    else
        congestedThreshold += serializationMS;
    if (UINT32_MAX - stableThreshold < serializationMS)
        stableThreshold = UINT32_MAX;
    else
        stableThreshold += serializationMS;
    const uint32_t clientWork = clientDecodeMS + clientRenderMS;
    uint32_t congestionFrameBytes = controller->currentBytesPerSec / 100u;
    if (congestionFrameBytes < RDP_TCP_MIN_CONGESTION_BYTES)
        congestionFrameBytes = RDP_TCP_MIN_CONGESTION_BYTES;
    if (congestionFrameBytes > RDP_TCP_MAX_CONGESTION_BYTES)
        congestionFrameBytes = RDP_TCP_MAX_CONGESTION_BYTES;
    const bool meaningfulNetworkSample = frameBytes >= congestionFrameBytes;

    const uint32_t severeThreshold = congestedThreshold <= UINT32_MAX / 2u
        ? congestedThreshold * 2u : UINT32_MAX;
    const bool useReliableUDPMetrics = transport &&
        transport->reliableUDPActive && transport->sampleFresh;
    const bool udpCongested = useReliableUDPMetrics &&
        !rdp_tcp_latency_transport_healthy(controller, transport);
    const bool legacyNetworkCongested =
        (controller->smoothedFeedbackMS > congestedThreshold &&
         feedbackElapsedMS > stableThreshold) ||
        feedbackElapsedMS > severeThreshold;
    const bool networkCongested = meaningfulNetworkSample &&
        (useReliableUDPMetrics ? udpCongested : legacyNetworkCongested);
    const bool clientCongested = clientWork > 120u;
    const bool congested = networkCongested || clientCongested;
    if (congested) {
        controller->stableFeedbackCount = 0;
        controller->stableLargeFeedbackCount = 0;
        if (controller->congestedFeedbackCount < UINT32_MAX)
            controller->congestedFeedbackCount++;
        if (controller->congestedFeedbackCount < RDP_TCP_CONGESTED_SAMPLES)
            return RDPTCPLatencyUnchanged;
        controller->congestedFeedbackCount = 0;
        return reduce_rate(controller, nowMS, 90u,
                           clientCongested ? RDPTCPLatencyCauseClient
                                           : RDPTCPLatencyCauseNetwork);
    }
    controller->congestedFeedbackCount = 0;

    const bool stableNetwork = useReliableUDPMetrics
        ? !udpCongested
        : controller->smoothedFeedbackMS <= stableThreshold;
    const bool stable = stableNetwork && clientWork <= 50u;
    if (!stable) {
        controller->stableFeedbackCount = 0;
        controller->stableLargeFeedbackCount = 0;
        return RDPTCPLatencyUnchanged;
    }

    uint32_t largeFrameBytes = controller->currentBytesPerSec / 20u;
    if (largeFrameBytes < 32768u) largeFrameBytes = 32768u;
    if (largeFrameBytes > 262144u) largeFrameBytes = 262144u;
    if (frameBytes >= largeFrameBytes &&
        controller->currentBytesPerSec >
            controller->confirmedCeilingBytesPerSec) {
        if (controller->stableLargeFeedbackCount < UINT32_MAX)
            controller->stableLargeFeedbackCount++;
        if (controller->stableLargeFeedbackCount >=
            RDP_TCP_LARGE_CONFIRM_SAMPLES) {
            controller->confirmedCeilingBytesPerSec =
                controller->currentBytesPerSec;
            controller->stableLargeFeedbackCount = 0;
        }
    }

    if (controller->stableFeedbackCount < UINT32_MAX)
        controller->stableFeedbackCount++;
    if (controller->stableFeedbackCount < RDP_TCP_RECOVERY_STABLE_SAMPLES ||
        nowMS - controller->lastRateChangeMS < RDP_TCP_RECOVERY_MIN_MS)
        return RDPTCPLatencyUnchanged;

    if (controller->currentBytesPerSec <
        controller->measuredCeilingBytesPerSec) {
        controller->stableFeedbackCount = 0;
        uint32_t step = controller->measuredCeilingBytesPerSec / 20u;
        if (step < 65536u) step = 65536u;
        uint64_t increased = (uint64_t)controller->currentBytesPerSec + step;
        if (increased > controller->measuredCeilingBytesPerSec)
            increased = controller->measuredCeilingBytesPerSec;
        controller->currentBytesPerSec = (uint32_t)increased;
        controller->lastAdjustmentCause = RDPTCPLatencyCauseNetwork;
        controller->lastRateChangeMS = nowMS;
        return RDPTCPLatencyIncreased;
    }

    /* The initial RDP bandwidth sample is only a starting point. When QoE has
     * stayed healthy at that ceiling, probe upward without reconnecting. Large
     * frames subsequently confirm the probe; real congestion rejects it via
     * reduce_rate above. */
    /* Never stack speculative probes based only on tiny idle updates. One
     * upward step must first be confirmed by rendered, payload-bearing frames;
     * otherwise the first real scroll after a quiet period can inherit a wildly
     * optimistic target and briefly flood the TCP path. */
    if (controller->currentBytesPerSec >
            controller->confirmedCeilingBytesPerSec ||
        controller->currentBytesPerSec >=
            controller->configuredCeilingBytesPerSec ||
        nowMS - controller->lastUpwardProbeMS <
            RDP_TCP_UPWARD_PROBE_MIN_MS)
        return RDPTCPLatencyUnchanged;

    controller->stableFeedbackCount = 0;
    uint32_t probeStep = (uint32_t)(
        (uint64_t)controller->currentBytesPerSec *
        RDP_TCP_UPWARD_PROBE_PERCENT / 100u);
    if (probeStep < RDP_TCP_UPWARD_PROBE_MIN_STEP)
        probeStep = RDP_TCP_UPWARD_PROBE_MIN_STEP;
    uint64_t probe = (uint64_t)controller->currentBytesPerSec + probeStep;
    if (probe > controller->configuredCeilingBytesPerSec)
        probe = controller->configuredCeilingBytesPerSec;
    controller->measuredCeilingBytesPerSec = (uint32_t)probe;
    controller->currentBytesPerSec = (uint32_t)probe;
    controller->lastAdjustmentCause = RDPTCPLatencyCauseNetwork;
    controller->lastRateChangeMS = nowMS;
    controller->lastUpwardProbeMS = nowMS;
    return RDPTCPLatencyProbed;
}

RDPTCPLatencyAdjustment rdp_tcp_latency_force_backoff(
    RDPTCPLatencyController *controller, uint64_t nowMS) {
    if (!controller) return RDPTCPLatencyUnchanged;
    return reduce_rate(controller, nowMS, 75u,
                       RDPTCPLatencyCauseClientQueue);
}
