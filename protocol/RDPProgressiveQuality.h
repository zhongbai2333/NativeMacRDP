#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool enabled;
    bool active;
    uint8_t baseQuantStep;
    uint8_t appliedQuantStep;
    uint32_t exitDelayMS;
    uint32_t minimumActiveMS;
    uint32_t entryFrameThreshold;
    uint32_t largeFrameStreak;
    uint64_t enteredAtMS;
    uint64_t lastLargeFrameMS;
    uint64_t switchCount;
    uint64_t motionFrameCount;
} RDPProgressiveQualityController;

typedef struct {
    uint8_t quantStep;
    bool changed;
    bool restoreFullFrame;
    bool largeMotion;
} RDPProgressiveQualityDecision;

void rdp_progressive_quality_init(RDPProgressiveQualityController *controller,
                                  bool enabled,
                                  uint8_t baseQuantStep,
                                  uint32_t exitDelayMS);

RDPProgressiveQualityDecision rdp_progressive_quality_update(
    RDPProgressiveQualityController *controller,
    uint32_t changedTiles,
    uint32_t totalTiles,
    uint32_t targetBytesPerSec,
    uint64_t nowMS);
