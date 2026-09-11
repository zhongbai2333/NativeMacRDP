#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    RDPTCPLatencyUnchanged = 0,
    RDPTCPLatencyReduced,
    RDPTCPLatencyIncreased,
    RDPTCPLatencyProbed,
} RDPTCPLatencyAdjustment;

typedef enum {
    RDPTCPLatencyCauseNone = 0,
    RDPTCPLatencyCauseNetwork,
    RDPTCPLatencyCauseClient,
    RDPTCPLatencyCauseClientQueue,
} RDPTCPLatencyCause;

/* A fresh snapshot from the reliable RDP-UDP2 data plane. End-to-end GFX QoE
 * includes client decode and render time, so it is not by itself evidence of
 * network congestion once Soft-Sync is active. */
typedef struct {
    bool reliableUDPActive;
    bool sampleFresh;
    bool recentLossOrRetransmit;
    uint32_t smoothedRTTMS;
    uint32_t inflightPackets;
    uint32_t congestionWindowPackets;
    uint32_t queuedBytes;
} RDPTransportFeedback;

/* Pure state machine for the TCP graphics pacing loop. It intentionally has
 * no FreeRDP dependency so the congestion policy can be unit-tested without a
 * live client. All calls are made from the peer thread; the resulting target
 * is mirrored to an atomic consumed by the capture thread. */
typedef struct {
    uint32_t minimumBytesPerSec;
    uint32_t configuredCeilingBytesPerSec;
    uint32_t measuredCeilingBytesPerSec;
    uint32_t confirmedCeilingBytesPerSec;
    uint32_t currentBytesPerSec;
    uint32_t baseRTTMS;
    uint32_t frameIntervalMS;
    uint32_t maxInflightFrames;
    uint32_t explicitMaxInflightFrames;
    uint32_t smoothedFeedbackMS;
    uint32_t stableFeedbackCount;
    uint32_t stableLargeFeedbackCount;
    uint32_t congestedFeedbackCount;
    RDPTCPLatencyCause lastAdjustmentCause;
    uint64_t lastRateChangeMS;
    uint64_t lastUpwardProbeMS;
} RDPTCPLatencyController;

bool rdp_tcp_latency_transport_healthy(
    const RDPTCPLatencyController *controller,
    const RDPTransportFeedback *transport);

void rdp_tcp_latency_init(RDPTCPLatencyController *controller,
                          uint32_t minimumBytesPerSec,
                          uint32_t configuredCeilingBytesPerSec,
                          uint32_t explicitMaxInflightFrames);

uint32_t rdp_tcp_latency_apply_network(RDPTCPLatencyController *controller,
                                       uint32_t bandwidthKbit,
                                       uint32_t baseRTTMS,
                                       uint64_t nowMS);

uint32_t rdp_tcp_latency_set_frame_interval(
    RDPTCPLatencyController *controller, uint32_t frameIntervalMS);

uint32_t rdp_tcp_latency_payload_inflight(uint32_t normalInflightFrames,
                                          uint32_t targetBytesPerSec,
                                          uint32_t lastFrameBytes);

/* End-to-end rendered-frame backpressure budget. Two RTTs keep TCP occupied
 * while bounding queued desktop data; conservative clamps cover missing or
 * noisy network-detection samples. */
uint32_t rdp_tcp_latency_inflight_budget(uint32_t targetBytesPerSec,
                                         uint32_t baseRTTMS,
                                         uint32_t smoothedFeedbackMS);

/* QoE ACKs can be batched by Windows App. Keep a strict frame cap for real
 * payload, but allow many tiny cursor/caret/metadata frames while their total
 * byte cost remains a small fraction of the BDP window. */
uint32_t rdp_tcp_latency_qoe_frame_limit(uint32_t explicitLimit,
                                         uint64_t inflightBytes,
                                         uint32_t inflightBudgetBytes);

/* Frame ACK and QoE ACK are independent cumulative progress signals. mstsc
 * can temporarily stop QoE ACKs while ordinary frame ACKs continue, whereas
 * Windows App can suspend ordinary ACKs while QoE remains current. Select the
 * newest signal with wrap-safe frame-ID ordering so either client can advance
 * the backpressure window. */
uint32_t rdp_tcp_latency_latest_feedback_frame(uint32_t qoeFrame,
                                               uint32_t frameAck,
                                               bool frameAckSeen);

RDPTCPLatencyAdjustment rdp_tcp_latency_on_feedback(
    RDPTCPLatencyController *controller,
    uint32_t feedbackElapsedMS,
    uint32_t frameBytes,
    uint32_t clientDecodeMS,
    uint32_t clientRenderMS,
    uint64_t feedbackCount,
    uint64_t nowMS);

RDPTCPLatencyAdjustment rdp_tcp_latency_on_feedback_with_transport(
    RDPTCPLatencyController *controller,
    uint32_t feedbackElapsedMS,
    uint32_t frameBytes,
    uint32_t clientDecodeMS,
    uint32_t clientRenderMS,
    const RDPTransportFeedback *transport,
    uint64_t feedbackCount,
    uint64_t nowMS);

RDPTCPLatencyAdjustment rdp_tcp_latency_force_backoff(
    RDPTCPLatencyController *controller, uint64_t nowMS);
