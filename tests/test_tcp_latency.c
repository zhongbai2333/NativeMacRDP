#include "protocol/RDPTCPLatency.h"

#include <assert.h>
#include <stdio.h>

static void test_network_budget_and_pipeline(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 7500000u, 0u);
    assert(rdp_tcp_latency_set_frame_interval(&c, 16u) == 4u);
    assert(rdp_tcp_latency_apply_network(&c, 16000u, 44u, 1000u) == 1500000u);
    assert(c.measuredCeilingBytesPerSec == 1500000u);
    assert(c.confirmedCeilingBytesPerSec == 1500000u);
    assert(c.maxInflightFrames == 4u);
}

static void test_explicit_pipeline_override(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 100u, 1000u, 2u);
    assert(rdp_tcp_latency_set_frame_interval(&c, 16u) == 2u);
    assert(rdp_tcp_latency_apply_network(&c, 8u, 200u, 0u) == 750u);
    assert(c.maxInflightFrames == 2u);
}

static void test_feedback_backoff_and_bounded_recovery(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 7500000u, 0u);
    rdp_tcp_latency_set_frame_interval(&c, 16u);
    assert(rdp_tcp_latency_apply_network(&c, 16000u, 44u, 1000u) == 1500000u);

    for (uint64_t i = 1; i < 8; i++)
        assert(rdp_tcp_latency_on_feedback(&c, 1000u, 1024u, 0u, 0u, i,
                                           1000u + i * 100u) ==
               RDPTCPLatencyUnchanged);
    assert(c.currentBytesPerSec == 1500000u);

    for (uint64_t i = 8; i < 30; i++)
        assert(rdp_tcp_latency_on_feedback(&c, 1000u, 1024u, 0u, 0u, i,
                                           2000u + i * 100u) ==
               RDPTCPLatencyUnchanged);
    assert(rdp_tcp_latency_on_feedback(&c, 1000u, 65536u, 0u, 0u, 30u,
                                       6000u) == RDPTCPLatencyUnchanged);
    assert(rdp_tcp_latency_on_feedback(&c, 1000u, 65536u, 0u, 0u, 31u,
                                       6100u) == RDPTCPLatencyUnchanged);
    assert(rdp_tcp_latency_on_feedback(&c, 1000u, 65536u, 0u, 0u, 32u,
                                       7600u) == RDPTCPLatencyReduced);
    assert(c.currentBytesPerSec == 1350000u);

    RDPTCPLatencyAdjustment last = RDPTCPLatencyUnchanged;
    for (uint64_t i = 33; i < 260; i++)
        last = rdp_tcp_latency_on_feedback(&c, 60u, 1024u, 2u, 2u, i,
                                           8000u + i * 50u);
    assert(last == RDPTCPLatencyUnchanged ||
           last == RDPTCPLatencyIncreased ||
           last == RDPTCPLatencyProbed);
    assert(c.currentBytesPerSec > 1350000u);
    assert(c.currentBytesPerSec <= c.measuredCeilingBytesPerSec);
    assert(c.currentBytesPerSec < c.configuredCeilingBytesPerSec);
}

static void test_large_frame_serialization_is_not_congestion(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 7500000u, 0u);
    rdp_tcp_latency_set_frame_interval(&c, 16u);
    assert(rdp_tcp_latency_apply_network(&c, 16000u, 44u, 1000u) == 1500000u);
    for (uint64_t i = 1; i <= 80; i++)
        assert(rdp_tcp_latency_on_feedback(&c, 250u, 270000u, 25u, 1u, i,
                                           2000u + i * 100u) ==
               RDPTCPLatencyUnchanged);
    assert(c.currentBytesPerSec == 1500000u);
}

static void test_worsening_link_and_large_frame_pipeline(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 7500000u, 0u);
    assert(rdp_tcp_latency_apply_network(&c, 16000u, 44u, 1000u) == 1500000u);
    for (uint64_t now = 3000u; now < 30000u; now += 2000u)
        (void)rdp_tcp_latency_force_backoff(&c, now);
    assert(c.currentBytesPerSec == 250000u);
    assert(c.confirmedCeilingBytesPerSec == 250000u);

    assert(rdp_tcp_latency_payload_inflight(4u, 1500000u, 60000u) == 4u);
    assert(rdp_tcp_latency_payload_inflight(4u, 1500000u, 75000u) == 2u);
    assert(rdp_tcp_latency_payload_inflight(3u, 5000000u, 200000u) == 3u);
    assert(rdp_tcp_latency_payload_inflight(3u, 5000000u, 260000u) == 2u);
    assert(rdp_tcp_latency_payload_inflight(2u, 1500000u, 300000u) == 2u);
}

static void test_byte_inflight_budget_tracks_bdp(void) {
    assert(rdp_tcp_latency_inflight_budget(1500000u, 44u, 0u) == 150000u);
    assert(rdp_tcp_latency_inflight_budget(250000u, 20u, 0u) == 131072u);
    assert(rdp_tcp_latency_inflight_budget(7500000u, 50u, 0u) == 750000u);
    assert(rdp_tcp_latency_inflight_budget(7500000u, 0u, 1000u) ==
           1048576u);
}

static void test_tiny_qoe_frames_get_a_byte_aware_safety_window(void) {
    assert(rdp_tcp_latency_qoe_frame_limit(0u, 4096u, 131072u) == 32u);
    assert(rdp_tcp_latency_qoe_frame_limit(0u, 50000u, 131072u) == 16u);
    assert(rdp_tcp_latency_qoe_frame_limit(0u, 100000u, 131072u) == 8u);
    assert(rdp_tcp_latency_qoe_frame_limit(5u, 0u, 131072u) == 5u);
}

static void test_frame_ack_can_advance_past_stale_qoe(void) {
    assert(rdp_tcp_latency_latest_feedback_frame(73u, 81u, true) == 81u);
    assert(rdp_tcp_latency_latest_feedback_frame(81u, 73u, true) == 81u);
    assert(rdp_tcp_latency_latest_feedback_frame(73u, 81u, false) == 73u);
    assert(rdp_tcp_latency_latest_feedback_frame(UINT32_MAX - 2u, 1u, true) ==
           1u);
    assert(rdp_tcp_latency_latest_feedback_frame(1u, UINT32_MAX - 2u, true) ==
           1u);
}

static void test_bad_initial_sample_probes_up_and_rejects_safely(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 7500000u, 0u);
    assert(rdp_tcp_latency_apply_network(&c, 4000u, 30u, 1000u) == 375000u);
    const uint32_t confirmed = c.confirmedCeilingBytesPerSec;

    RDPTCPLatencyAdjustment adjustment = RDPTCPLatencyUnchanged;
    for (uint64_t i = 1; i <= 160; i++) {
        adjustment = rdp_tcp_latency_on_feedback(
            &c, 45u, 1024u, 1u, 0u, i, 1000u + i * 100u);
        if (adjustment == RDPTCPLatencyProbed)
            break;
    }
    assert(adjustment == RDPTCPLatencyProbed);
    assert(c.currentBytesPerSec > confirmed);
    assert(c.confirmedCeilingBytesPerSec == confirmed);

    const uint64_t congestedAt = c.lastRateChangeMS + 1600u;
    assert(rdp_tcp_latency_on_feedback(&c, 2000u, 65536u, 0u, 0u, 161u,
                                       congestedAt) == RDPTCPLatencyUnchanged);
    assert(rdp_tcp_latency_on_feedback(&c, 2000u, 65536u, 0u, 0u, 162u,
                                       congestedAt + 10u) == RDPTCPLatencyUnchanged);
    assert(rdp_tcp_latency_on_feedback(&c, 2000u, 65536u, 0u, 0u, 163u,
                                       congestedAt + 20u) == RDPTCPLatencyReduced);
    assert(c.currentBytesPerSec == confirmed);
    assert(c.measuredCeilingBytesPerSec == confirmed);
}

static void test_large_frames_confirm_successful_probe(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 7500000u, 0u);
    assert(rdp_tcp_latency_apply_network(&c, 4000u, 30u, 1000u) == 375000u);
    for (uint64_t i = 1; i <= 160; i++) {
        if (rdp_tcp_latency_on_feedback(&c, 45u, 1024u, 1u, 0u, i,
                                        1000u + i * 100u) ==
            RDPTCPLatencyProbed)
            break;
    }
    const uint32_t probe = c.currentBytesPerSec;
    assert(probe > c.confirmedCeilingBytesPerSec);
    for (uint64_t i = 161; i < 169; i++)
        (void)rdp_tcp_latency_on_feedback(&c, 180u, 100000u, 10u, 1u, i,
                                          18000u + i * 20u);
    assert(c.confirmedCeilingBytesPerSec == probe);
}

static void test_tiny_idle_feedback_cannot_stack_upward_probes(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 7500000u, 0u);
    assert(rdp_tcp_latency_apply_network(&c, 4000u, 30u, 1000u) == 375000u);

    uint32_t probes = 0u;
    for (uint64_t i = 1u; i <= 1000u; i++) {
        if (rdp_tcp_latency_on_feedback(&c, 45u, 1024u, 1u, 0u, i,
                                        1000u + i * 100u) ==
            RDPTCPLatencyProbed)
            probes++;
    }
    assert(probes == 1u);
    assert(c.currentBytesPerSec > c.confirmedCeilingBytesPerSec);
    assert(c.currentBytesPerSec ==
           c.confirmedCeilingBytesPerSec + 125000u);
}

static void test_queue_backoff_cooldown(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 1000000u, 0u);
    assert(rdp_tcp_latency_force_backoff(&c, 500u) == RDPTCPLatencyUnchanged);
    assert(rdp_tcp_latency_force_backoff(&c, 1500u) == RDPTCPLatencyReduced);
    assert(c.currentBytesPerSec == 750000u);
    assert(rdp_tcp_latency_force_backoff(&c, 2000u) == RDPTCPLatencyUnchanged);
}

static void test_delayed_tiny_frames_do_not_fake_congestion(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 1500000u, 0u);
    assert(rdp_tcp_latency_apply_network(&c, 16000u, 30u, 1000u) ==
           1500000u);
    for (uint64_t i = 1u; i < 30u; i++)
        (void)rdp_tcp_latency_on_feedback(
            &c, 50u, 1024u, 0u, 0u, i, 1000u + i * 50u);
    for (uint64_t i = 30u; i < 40u; i++)
        assert(rdp_tcp_latency_on_feedback(
                   &c, 1000u, 1024u, 0u, 0u, i, 4000u + i * 100u) ==
               RDPTCPLatencyUnchanged);
    assert(c.currentBytesPerSec == 1500000u);
}

static RDPTransportFeedback healthy_udp(void) {
    return (RDPTransportFeedback){
        .reliableUDPActive = true,
        .sampleFresh = true,
        .recentLossOrRetransmit = false,
        .smoothedRTTMS = 1u,
        .inflightPackets = 2u,
        .congestionWindowPackets = 4096u,
        .queuedBytes = 0u,
    };
}

static void test_healthy_udp_separates_render_feedback_from_network(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 7500000u, 0u);
    assert(rdp_tcp_latency_apply_network(&c, 64000u, 1u, 1000u) ==
           6000000u);
    RDPTransportFeedback udp = healthy_udp();
    assert(rdp_tcp_latency_transport_healthy(&c, &udp));
    for (uint64_t i = 1u; i <= 90u; i++)
        assert(rdp_tcp_latency_on_feedback_with_transport(
                   &c, 450u, 300000u, 10u, 30u, &udp, i,
                   1000u + i * 50u) != RDPTCPLatencyReduced);
    assert(c.currentBytesPerSec == 6000000u);
}

static void test_udp_loss_and_client_pressure_still_back_off(void) {
    RDPTCPLatencyController c;
    rdp_tcp_latency_init(&c, 250000u, 7500000u, 0u);
    assert(rdp_tcp_latency_apply_network(&c, 64000u, 1u, 1000u) ==
           6000000u);
    RDPTransportFeedback udp = healthy_udp();
    udp.recentLossOrRetransmit = true;
    assert(!rdp_tcp_latency_transport_healthy(&c, &udp));
    for (uint64_t i = 1u; i < 32u; i++)
        (void)rdp_tcp_latency_on_feedback_with_transport(
            &c, 40u, 300000u, 5u, 5u, &udp, i, 1000u + i * 50u);
    assert(rdp_tcp_latency_on_feedback_with_transport(
               &c, 40u, 300000u, 5u, 5u, &udp, 32u, 4000u) ==
           RDPTCPLatencyReduced);
    assert(c.lastAdjustmentCause == RDPTCPLatencyCauseNetwork);

    RDPTCPLatencyController client;
    rdp_tcp_latency_init(&client, 250000u, 7500000u, 0u);
    assert(rdp_tcp_latency_apply_network(&client, 64000u, 1u, 1000u) ==
           6000000u);
    udp = healthy_udp();
    for (uint64_t i = 1u; i < 32u; i++)
        (void)rdp_tcp_latency_on_feedback_with_transport(
            &client, 40u, 300000u, 80u, 60u, &udp, i,
            1000u + i * 50u);
    assert(rdp_tcp_latency_on_feedback_with_transport(
               &client, 40u, 300000u, 80u, 60u, &udp, 32u, 4000u) ==
           RDPTCPLatencyReduced);
    assert(client.lastAdjustmentCause == RDPTCPLatencyCauseClient);
}

int main(void) {
    test_network_budget_and_pipeline();
    test_explicit_pipeline_override();
    test_feedback_backoff_and_bounded_recovery();
    test_large_frame_serialization_is_not_congestion();
    test_worsening_link_and_large_frame_pipeline();
    test_byte_inflight_budget_tracks_bdp();
    test_tiny_qoe_frames_get_a_byte_aware_safety_window();
    test_frame_ack_can_advance_past_stale_qoe();
    test_bad_initial_sample_probes_up_and_rejects_safely();
    test_large_frames_confirm_successful_probe();
    test_tiny_idle_feedback_cannot_stack_upward_probes();
    test_queue_backoff_cooldown();
    test_delayed_tiny_frames_do_not_fake_congestion();
    test_healthy_udp_separates_render_feedback_from_network();
    test_udp_loss_and_client_pressure_still_back_off();
    puts("tcp latency controller tests passed");
    return 0;
}
