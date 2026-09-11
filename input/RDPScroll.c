#include "input/RDPScroll.h"

#include <math.h>

int32_t rdp_scroll_decode_rotation(uint16_t pointerFlags) {
    /* MS-RDPBCGR encodes WheelRotation as a signed 9-bit integer. Bit 8 is
     * not a separate "negate the low byte" flag: 0x1FE is -2, not -254. */
    int32_t rotation = pointerFlags & 0x01FFu;
    if (rotation & 0x0100u)
        rotation -= 0x0200;
    return rotation;
}

int32_t rdp_scroll_rotation_to_pixels(int32_t rotation, double scale) {
    if (rotation == 0) return 0;
    if (!isfinite(scale) || scale < 0.25 || scale > 8.0)
        scale = 1.0;

    double pixels = (double)rotation * scale;
    if (pixels > 4096.0) pixels = 4096.0;
    if (pixels < -4096.0) pixels = -4096.0;

    int32_t rounded = (int32_t)lround(pixels);
    if (rounded == 0)
        rounded = rotation > 0 ? 1 : -1;
    return rounded;
}

int32_t rdp_scroll_rotation_to_horizontal_pixels(int32_t rotation,
                                                 double scale) {
    return -rdp_scroll_rotation_to_pixels(rotation, scale);
}
