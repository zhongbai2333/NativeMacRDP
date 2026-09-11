#include "protocol/RDPProgressiveQuality.h"

#include <assert.h>
#include <stdio.h>

static void test_motion_entry_and_delayed_restore(void) {
    RDPProgressiveQualityController c;
    rdp_progressive_quality_init(&c, true, 1u, 750u);

    RDPProgressiveQualityDecision d = rdp_progressive_quality_update(
        &c, 10u, 561u, 4000000u, 1000u);
    assert(!d.largeMotion && !d.changed && d.quantStep == 0u);

    d = rdp_progressive_quality_update(&c, 200u, 561u, 4000000u, 1100u);
    assert(d.largeMotion && !d.changed && d.quantStep == 0u);

    d = rdp_progressive_quality_update(&c, 200u, 561u, 4000000u, 1150u);
    assert(d.largeMotion && d.changed && d.quantStep == 1u);
    assert(c.active);

    d = rdp_progressive_quality_update(&c, 2u, 561u, 4000000u, 1800u);
    assert(!d.changed && !d.restoreFullFrame && d.quantStep == 1u);

    d = rdp_progressive_quality_update(&c, 2u, 561u, 4000000u, 1900u);
    assert(d.changed && d.restoreFullFrame && d.quantStep == 0u);
    assert(!c.active);
}

static void test_weak_link_uses_stronger_motion_quantization(void) {
    RDPProgressiveQualityController c;
    rdp_progressive_quality_init(&c, true, 1u, 750u);

    RDPProgressiveQualityDecision d = rdp_progressive_quality_update(
        &c, 120u, 561u, 1500000u, 1000u);
    assert(!d.changed && d.quantStep == 0u);

    d = rdp_progressive_quality_update(
        &c, 120u, 561u, 1500000u, 1050u);
    assert(d.changed);
    assert(d.quantStep == 2u);

    d = rdp_progressive_quality_update(&c, 120u, 561u, 900000u, 1100u);
    assert(d.changed && d.quantStep == 3u);
}

static void test_single_large_frame_does_not_thrash_quality(void) {
    RDPProgressiveQualityController c;
    rdp_progressive_quality_init(&c, true, 1u, 750u);
    RDPProgressiveQualityDecision d = rdp_progressive_quality_update(
        &c, 120u, 561u, 4000000u, 1000u);
    assert(d.largeMotion && !d.changed && !c.active);
    d = rdp_progressive_quality_update(
        &c, 1u, 561u, 4000000u, 1050u);
    assert(!d.largeMotion && !d.changed && c.switchCount == 0u);
}

static void test_overwhelming_change_enters_immediately(void) {
    RDPProgressiveQualityController c;
    rdp_progressive_quality_init(&c, true, 1u, 750u);
    RDPProgressiveQualityDecision d = rdp_progressive_quality_update(
        &c, 400u, 561u, 4000000u, 1000u);
    assert(d.largeMotion && d.changed && d.quantStep == 1u && c.active);
}

static void test_disabled_controller_is_inert(void) {
    RDPProgressiveQualityController c;
    rdp_progressive_quality_init(&c, false, 1u, 750u);
    RDPProgressiveQualityDecision d = rdp_progressive_quality_update(
        &c, 561u, 561u, 250000u, 1000u);
    assert(!d.largeMotion && !d.changed && !d.restoreFullFrame);
}

int main(void) {
    test_motion_entry_and_delayed_restore();
    test_weak_link_uses_stronger_motion_quantization();
    test_single_large_frame_does_not_thrash_quality();
    test_overwhelming_change_enters_immediately();
    test_disabled_controller_is_inert();
    puts("progressive quality controller tests passed");
    return 0;
}
