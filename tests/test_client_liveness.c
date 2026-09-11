#include "protocol/RDPClientLiveness.h"

#include <assert.h>
#include <stdio.h>

static RDPClientLivenessSnapshot healthy_snapshot(void) {
    return (RDPClientLivenessSnapshot){
        .activated = true,
        .gfxReady = true,
        .feedbackSeen = true,
        .sentFrameId = 101u,
        .ackFrameId = 100u,
        .qoeFrameId = 100u,
        .lastResponseMS = 1000u,
    };
}
int main(void) {
    RDPClientLivenessSnapshot s = healthy_snapshot();
    assert(!rdp_client_liveness_timed_out(&s, 20999u, 20000u));
    assert(!rdp_client_liveness_timed_out(&s, 21000u, 20000u));
    s.sentFrameId = 102u;
    assert(rdp_client_liveness_timed_out(&s, 21000u, 20000u));

    s.outputSuppressed = true;
    s.suppressedSinceMS = 2000u;
    assert(!rdp_client_liveness_suppressed_probe_due(&s, 3499u, 1500u));
    assert(rdp_client_liveness_suppressed_probe_due(&s, 3500u, 1500u));
    assert(!rdp_client_liveness_timed_out(&s, 21999u, 20000u));
    assert(rdp_client_liveness_timed_out(&s, 22000u, 20000u));

    s.suppressedSinceMS = 0u;
    assert(!rdp_client_liveness_suppressed_probe_due(&s, 99999u, 1500u));
    assert(!rdp_client_liveness_timed_out(&s, 99999u, 20000u));

    assert(!rdp_client_liveness_surface_resync_due(
        false, 749u, 1499u, 750u, 1500u));
    assert(rdp_client_liveness_surface_resync_due(
        false, 750u, 0u, 750u, 1500u));
    assert(rdp_client_liveness_surface_resync_due(
        false, 0u, 1500u, 750u, 1500u));
    assert(rdp_client_liveness_surface_resync_due(
        true, 0u, 0u, 750u, 1500u));
    assert(!rdp_client_liveness_surface_resync_due(
        false, UINT64_MAX, UINT64_MAX, 0u, 0u));

    s = healthy_snapshot();
    s.feedbackSeen = false;
    assert(!rdp_client_liveness_timed_out(&s, 99999u, 20000u));

    s = healthy_snapshot();
    s.ackFrameId = s.sentFrameId;
    assert(!rdp_client_liveness_timed_out(&s, 99999u, 20000u));

    s = healthy_snapshot();
    s.qoeFrameId = s.sentFrameId;
    assert(!rdp_client_liveness_timed_out(&s, 99999u, 20000u));

    /* Frame sequence comparison remains valid across uint32 wrap. */
    s = healthy_snapshot();
    s.ackFrameId = UINT32_MAX - 2u;
    s.qoeFrameId = UINT32_MAX - 1u;
    s.sentFrameId = 2u;
    assert(rdp_client_liveness_timed_out(&s, 21000u, 20000u));

    puts("client liveness tests passed");
    return 0;
}
