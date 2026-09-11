#include "protocol/RDPProgressiveQuality.h"

#define RDP_MOTION_MIN_TILES 32u
#define RDP_MOTION_TILE_DIVISOR 8u
#define RDP_MOTION_IMMEDIATE_DIVISOR 2u
#define RDP_MOTION_WEAK_TARGET_BPS 2000000u
#define RDP_MOTION_VERY_WEAK_TARGET_BPS 1000000u
#define RDP_MOTION_ENTRY_FRAMES 2u

static uint8_t clamp_step(uint8_t step) {
    if (step < 1u) return 1u;
    if (step > 3u) return 3u;
    return step;
}

void rdp_progressive_quality_init(RDPProgressiveQualityController *controller,
                                  bool enabled,
                                  uint8_t baseQuantStep,
                                  uint32_t exitDelayMS) {
    if (!controller) return;
    *controller = (RDPProgressiveQualityController){0};
    controller->enabled = enabled;
    controller->baseQuantStep = clamp_step(baseQuantStep);
    controller->exitDelayMS = exitDelayMS ? exitDelayMS : 1200u;
    controller->minimumActiveMS = controller->exitDelayMS;
    controller->entryFrameThreshold = RDP_MOTION_ENTRY_FRAMES;
}

RDPProgressiveQualityDecision rdp_progressive_quality_update(
    RDPProgressiveQualityController *controller,
    uint32_t changedTiles,
    uint32_t totalTiles,
    uint32_t targetBytesPerSec,
    uint64_t nowMS) {
    RDPProgressiveQualityDecision decision = {0};
    if (!controller || !controller->enabled)
        return decision;

    uint32_t motionThreshold = totalTiles / RDP_MOTION_TILE_DIVISOR;
    if (motionThreshold < RDP_MOTION_MIN_TILES)
        motionThreshold = RDP_MOTION_MIN_TILES;
    const bool largeMotion = changedTiles >= motionThreshold;
    const bool overwhelmingMotion = totalTiles > 0u &&
        changedTiles >= totalTiles / RDP_MOTION_IMMEDIATE_DIVISOR;
    decision.largeMotion = largeMotion;

    if (largeMotion) {
        uint8_t desiredStep = controller->baseQuantStep;
        if (targetBytesPerSec < RDP_MOTION_VERY_WEAK_TARGET_BPS &&
            desiredStep < 3u)
            desiredStep = 3u;
        else if (targetBytesPerSec < RDP_MOTION_WEAK_TARGET_BPS &&
                 desiredStep < 2u)
            desiredStep = 2u;

        controller->lastLargeFrameMS = nowMS;
        controller->motionFrameCount++;
        if (!controller->active) {
            controller->largeFrameStreak++;
            if (!overwhelmingMotion && controller->largeFrameStreak <
                controller->entryFrameThreshold) {
                decision.quantStep = 0u;
                return decision;
            }
            controller->active = true;
            controller->enteredAtMS = nowMS;
        }
        if (controller->appliedQuantStep != desiredStep) {
            controller->appliedQuantStep = desiredStep;
            controller->switchCount++;
            decision.changed = true;
        }
        decision.quantStep = desiredStep;
        return decision;
    }

    controller->largeFrameStreak = 0u;
    if (controller->active && nowMS >= controller->lastLargeFrameMS &&
        nowMS - controller->lastLargeFrameMS >= controller->exitDelayMS &&
        nowMS >= controller->enteredAtMS &&
        nowMS - controller->enteredAtMS >= controller->minimumActiveMS) {
        controller->active = false;
        controller->appliedQuantStep = 0u;
        controller->switchCount++;
        decision.changed = true;
        decision.restoreFullFrame = true;
    } else {
        decision.quantStep = controller->appliedQuantStep;
    }
    return decision;
}
