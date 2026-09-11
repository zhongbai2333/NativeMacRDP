#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int32_t shiftX;
    int32_t shiftY;
    uint32_t destinationLeft;
    uint32_t destinationTop;
    uint32_t destinationRight;
    uint32_t destinationBottom;
    uint32_t matchedTiles;
} RDPFrameReuseMatch;

/* Find a large tile-aligned rectangle whose current pixels are an exact axial
 * translation of the last client-visible reference. Exact full-tile validation
 * makes the command safe even when the initial sampled motion estimate is
 * ambiguous. tileMask uses the same 64x64 row-major layout as Progressive. */
bool rdp_frame_reuse_find_axis_translation(
    const uint8_t *currentPixels, size_t currentStride,
    const uint8_t *referencePixels, size_t referenceStride,
    uint32_t width, uint32_t height,
    const uint8_t *tileMask, uint32_t tileColumns, uint32_t tileRows,
    uint32_t maxShiftPixels, uint32_t minimumMatchedTiles,
    RDPFrameReuseMatch *match);

/* Mirror a successful client SurfaceToSurface operation into the server-side
 * reference image. memmove ordering preserves overlapping scroll regions. */
void rdp_frame_reuse_apply_reference(
    uint8_t *referencePixels, size_t referenceStride,
    const RDPFrameReuseMatch *match);
