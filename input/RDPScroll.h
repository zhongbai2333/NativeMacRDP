#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Decode the signed 9-bit WheelRotation field carried in pointer flags. */
int32_t rdp_scroll_decode_rotation(uint16_t pointerFlags);

/* Preserve high-resolution wheel magnitude while applying a bounded user
 * scale for macOS pixel-unit scroll injection. */
int32_t rdp_scroll_rotation_to_pixels(int32_t rotation, double scale);

/* Quartz's horizontal scroll axis is opposite to the RDP WheelRotation axis.
 * Keep vertical conversion unchanged and invert only horizontal injection. */
int32_t rdp_scroll_rotation_to_horizontal_pixels(int32_t rotation,
                                                 double scale);

#ifdef __cplusplus
}
#endif
