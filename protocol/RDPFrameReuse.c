#include "protocol/RDPFrameReuse.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define RDP_REUSE_TILE_SIZE 64u
#define RDP_REUSE_MAX_SAMPLES 384u

typedef struct {
    uint16_t x;
    uint16_t y;
    uint32_t signature[4];
} RDPReuseSample;

typedef struct {
    int32_t dx;
    int32_t dy;
    uint32_t score;
} RDPReuseCandidate;

static void load_signature(const uint8_t *pixels, size_t stride,
                           uint32_t x, uint32_t y, uint32_t signature[4]) {
    memcpy(&signature[0], pixels + (size_t)y * stride + (size_t)x * 4u, 4u);
    memcpy(&signature[1], pixels + (size_t)y * stride + (size_t)(x + 7u) * 4u, 4u);
    memcpy(&signature[2], pixels + (size_t)(y + 7u) * stride + (size_t)x * 4u, 4u);
    memcpy(&signature[3], pixels + (size_t)(y + 7u) * stride +
                          (size_t)(x + 7u) * 4u, 4u);
}
static bool signatures_equal(const uint32_t left[4],
                             const uint32_t right[4]) {
    return left[0] == right[0] && left[1] == right[1] &&
           left[2] == right[2] && left[3] == right[3];
}

static uint32_t collect_samples(const uint8_t *current, size_t currentStride,
                                const uint8_t *reference, size_t referenceStride,
                                uint32_t width, uint32_t height,
                                const uint8_t *tileMask,
                                uint32_t tileColumns, uint32_t tileRows,
                                RDPReuseSample samples[RDP_REUSE_MAX_SAMPLES]) {
    static const uint8_t offsets[] = { 8u, 24u, 40u, 55u };
    uint32_t count = 0u;
    uint32_t seen = 0u;
    uint32_t randomState = 0x9E3779B9u;

    for (uint32_t ty = 0; ty < tileRows; ty++) {
        for (uint32_t tx = 0; tx < tileColumns; tx++) {
            const size_t tile = (size_t)ty * tileColumns + tx;
            if (!tileMask[tile]) continue;
            const uint32_t tileLeft = tx * RDP_REUSE_TILE_SIZE;
            const uint32_t tileTop = ty * RDP_REUSE_TILE_SIZE;
            for (size_t oi = 0; oi < sizeof(offsets); oi++) {
                uint32_t x = tileLeft + offsets[oi];
                uint32_t y = tileTop + offsets[(oi + ty + tx) % sizeof(offsets)];
                if (x + 7u >= width || y + 7u >= height) continue;

                uint32_t currentSignature[4];
                uint32_t referenceSignature[4];
                load_signature(current, currentStride, x, y, currentSignature);
                load_signature(reference, referenceStride, x, y,
                               referenceSignature);
                if (signatures_equal(currentSignature, referenceSignature))
                    continue;

                RDPReuseSample sample = { .x = (uint16_t)x, .y = (uint16_t)y };
                memcpy(sample.signature, currentSignature,
                       sizeof(sample.signature));
                seen++;
                if (count < RDP_REUSE_MAX_SAMPLES) {
                    samples[count++] = sample;
                    continue;
                }
                /* Deterministic reservoir sampling prevents a large topmost
                 * damage rectangle from hiding motion lower on the screen. */
                randomState = randomState * 1664525u + 1013904223u;
                uint32_t replacement = randomState % seen;
                if (replacement < RDP_REUSE_MAX_SAMPLES)
                    samples[replacement] = sample;
            }
        }
    }
    return count;
}

static uint32_t score_candidate(const RDPReuseSample *samples,
                                uint32_t sampleCount,
                                const uint8_t *reference,
                                size_t referenceStride,
                                uint32_t width, uint32_t height,
                                int32_t dx, int32_t dy) {
    uint32_t score = 0u;
    for (uint32_t i = 0; i < sampleCount; i++) {
        int32_t sourceX = (int32_t)samples[i].x - dx;
        int32_t sourceY = (int32_t)samples[i].y - dy;
        if (sourceX < 0 || sourceY < 0 ||
            sourceX + 7 >= (int32_t)width ||
            sourceY + 7 >= (int32_t)height)
            continue;
        uint32_t signature[4];
        load_signature(reference, referenceStride,
                       (uint32_t)sourceX, (uint32_t)sourceY, signature);
        if (signatures_equal(samples[i].signature, signature)) score++;
    }
    return score;
}

static bool tile_matches_translation(const uint8_t *current,
                                     size_t currentStride,
                                     const uint8_t *reference,
                                     size_t referenceStride,
                                     uint32_t width, uint32_t height,
                                     uint32_t tx, uint32_t ty,
                                     int32_t dx, int32_t dy) {
    uint32_t left = tx * RDP_REUSE_TILE_SIZE;
    uint32_t top = ty * RDP_REUSE_TILE_SIZE;
    uint32_t right = left + RDP_REUSE_TILE_SIZE;
    uint32_t bottom = top + RDP_REUSE_TILE_SIZE;
    if (right > width) right = width;
    if (bottom > height) bottom = height;
    int32_t sourceLeft = (int32_t)left - dx;
    int32_t sourceTop = (int32_t)top - dy;
    int32_t sourceRight = (int32_t)right - dx;
    int32_t sourceBottom = (int32_t)bottom - dy;
    if (sourceLeft < 0 || sourceTop < 0 ||
        sourceRight > (int32_t)width || sourceBottom > (int32_t)height)
        return false;

    const size_t rowBytes = (size_t)(right - left) * 4u;
    for (uint32_t y = top; y < bottom; y++) {
        const uint8_t *currentRow = current + (size_t)y * currentStride +
                                    (size_t)left * 4u;
        const uint8_t *referenceRow = reference +
            (size_t)((int32_t)y - dy) * referenceStride +
            (size_t)sourceLeft * 4u;
        if (memcmp(currentRow, referenceRow, rowBytes) != 0) return false;
    }
    return true;
}

static bool largest_matching_rectangle(
    const uint8_t *current, size_t currentStride,
    const uint8_t *reference, size_t referenceStride,
    uint32_t width, uint32_t height,
    const uint8_t *tileMask, uint32_t tileColumns, uint32_t tileRows,
    const RDPReuseCandidate *candidate, RDPFrameReuseMatch *match) {
    uint32_t *heights = calloc(tileColumns, sizeof(*heights));
    uint32_t *stack = calloc(tileColumns + 1u, sizeof(*stack));
    if (!heights || !stack) {
        free(heights);
        free(stack);
        return false;
    }

    uint32_t bestArea = 0u;
    uint32_t bestLeft = 0u, bestRight = 0u;
    uint32_t bestTop = 0u, bestBottom = 0u;
    for (uint32_t ty = 0; ty < tileRows; ty++) {
        for (uint32_t tx = 0; tx < tileColumns; tx++) {
            const size_t tile = (size_t)ty * tileColumns + tx;
            const bool matches = tileMask[tile] && tile_matches_translation(
                current, currentStride, reference, referenceStride,
                width, height, tx, ty, candidate->dx, candidate->dy);
            heights[tx] = matches ? heights[tx] + 1u : 0u;
        }

        uint32_t stackSize = 0u;
        for (uint32_t x = 0; x <= tileColumns; x++) {
            const uint32_t heightHere = x < tileColumns ? heights[x] : 0u;
            while (stackSize && heights[stack[stackSize - 1u]] > heightHere) {
                const uint32_t index = stack[--stackSize];
                const uint32_t h = heights[index];
                const uint32_t left = stackSize ? stack[stackSize - 1u] + 1u : 0u;
                const uint32_t area = h * (x - left);
                if (area > bestArea) {
                    bestArea = area;
                    bestLeft = left;
                    bestRight = x;
                    bestBottom = ty + 1u;
                    bestTop = bestBottom - h;
                }
            }
            stack[stackSize++] = x;
        }
    }
    free(heights);
    free(stack);
    if (!bestArea) return false;

    *match = (RDPFrameReuseMatch){
        .shiftX = candidate->dx,
        .shiftY = candidate->dy,
        .destinationLeft = bestLeft * RDP_REUSE_TILE_SIZE,
        .destinationTop = bestTop * RDP_REUSE_TILE_SIZE,
        .destinationRight = bestRight * RDP_REUSE_TILE_SIZE,
        .destinationBottom = bestBottom * RDP_REUSE_TILE_SIZE,
        .matchedTiles = bestArea,
    };
    if (match->destinationRight > width) match->destinationRight = width;
    if (match->destinationBottom > height) match->destinationBottom = height;
    return true;
}

bool rdp_frame_reuse_find_axis_translation(
    const uint8_t *currentPixels, size_t currentStride,
    const uint8_t *referencePixels, size_t referenceStride,
    uint32_t width, uint32_t height,
    const uint8_t *tileMask, uint32_t tileColumns, uint32_t tileRows,
    uint32_t maxShiftPixels, uint32_t minimumMatchedTiles,
    RDPFrameReuseMatch *match) {
    if (match) *match = (RDPFrameReuseMatch){0};
    if (!currentPixels || !referencePixels || !tileMask || !match ||
        !width || !height || !tileColumns || !tileRows ||
        currentStride < (size_t)width * 4u ||
        referenceStride < (size_t)width * 4u)
        return false;

    RDPReuseSample samples[RDP_REUSE_MAX_SAMPLES];
    const uint32_t sampleCount = collect_samples(
        currentPixels, currentStride, referencePixels, referenceStride,
        width, height, tileMask, tileColumns, tileRows, samples);
    if (sampleCount < 12u) return false;

    RDPReuseCandidate candidates[2] = {0};
    uint32_t verticalLimit = maxShiftPixels;
    uint32_t horizontalLimit = maxShiftPixels;
    if (verticalLimit >= height) verticalLimit = height - 1u;
    if (horizontalLimit >= width) horizontalLimit = width - 1u;
    for (int32_t dy = -(int32_t)verticalLimit;
         dy <= (int32_t)verticalLimit; dy++) {
        if (!dy) continue;
        uint32_t score = score_candidate(samples, sampleCount, referencePixels,
                                         referenceStride, width, height, 0, dy);
        if (score > candidates[0].score)
            candidates[0] = (RDPReuseCandidate){ .dx = 0, .dy = dy,
                                                  .score = score };
    }
    for (int32_t dx = -(int32_t)horizontalLimit;
         dx <= (int32_t)horizontalLimit; dx++) {
        if (!dx) continue;
        uint32_t score = score_candidate(samples, sampleCount, referencePixels,
                                         referenceStride, width, height, dx, 0);
        if (score > candidates[1].score)
            candidates[1] = (RDPReuseCandidate){ .dx = dx, .dy = 0,
                                                  .score = score };
    }

    RDPFrameReuseMatch best = {0};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (candidates[i].score < 12u ||
            candidates[i].score * 5u < sampleCount)
            continue;
        RDPFrameReuseMatch candidateMatch = {0};
        if (!largest_matching_rectangle(
                currentPixels, currentStride, referencePixels, referenceStride,
                width, height, tileMask, tileColumns, tileRows,
                &candidates[i], &candidateMatch))
            continue;
        if (candidateMatch.matchedTiles > best.matchedTiles)
            best = candidateMatch;
    }
    if (best.matchedTiles < minimumMatchedTiles) return false;
    *match = best;
    return true;
}

void rdp_frame_reuse_apply_reference(
    uint8_t *referencePixels, size_t referenceStride,
    const RDPFrameReuseMatch *match) {
    if (!referencePixels || !referenceStride || !match ||
        match->destinationLeft >= match->destinationRight ||
        match->destinationTop >= match->destinationBottom)
        return;

    const int32_t sourceLeft = (int32_t)match->destinationLeft - match->shiftX;
    const int32_t sourceTop = (int32_t)match->destinationTop - match->shiftY;
    if (sourceLeft < 0 || sourceTop < 0) return;
    const size_t rowBytes =
        (size_t)(match->destinationRight - match->destinationLeft) * 4u;
    const uint32_t rows = match->destinationBottom - match->destinationTop;
    if (match->destinationTop > (uint32_t)sourceTop) {
        for (uint32_t offset = rows; offset > 0u; offset--) {
            uint32_t destinationY = match->destinationTop + offset - 1u;
            uint32_t sourceY = (uint32_t)sourceTop + offset - 1u;
            memmove(referencePixels + (size_t)destinationY * referenceStride +
                        (size_t)match->destinationLeft * 4u,
                    referencePixels + (size_t)sourceY * referenceStride +
                        (size_t)sourceLeft * 4u,
                    rowBytes);
        }
    } else {
        for (uint32_t offset = 0u; offset < rows; offset++) {
            uint32_t destinationY = match->destinationTop + offset;
            uint32_t sourceY = (uint32_t)sourceTop + offset;
            memmove(referencePixels + (size_t)destinationY * referenceStride +
                        (size_t)match->destinationLeft * 4u,
                    referencePixels + (size_t)sourceY * referenceStride +
                        (size_t)sourceLeft * 4u,
                    rowBytes);
        }
    }
}
