#include "input/RDPScroll.h"

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    /* Vertical positive values observed from Windows App. */
    assert(rdp_scroll_decode_rotation(0x0201u) == 1);
    assert(rdp_scroll_decode_rotation(0x0208u) == 8);
    assert(rdp_scroll_decode_rotation(0x0278u) == 120);

    /* Bit 8 sign-extends the complete 9-bit value. These exact flags occurred
     * in the iPad logs; the old decoder incorrectly produced -255/-254/-251. */
    assert(rdp_scroll_decode_rotation(0x03FFu) == -1);
    assert(rdp_scroll_decode_rotation(0x03FEu) == -2);
    assert(rdp_scroll_decode_rotation(0x03FBu) == -5);
    assert(rdp_scroll_decode_rotation(0x0388u) == -120);

    /* Horizontal wheel uses the same signed rotation field. */
    assert(rdp_scroll_decode_rotation(0x0401u) == 1);
    assert(rdp_scroll_decode_rotation(0x05FFu) == -1);

    assert(rdp_scroll_rotation_to_pixels(2, 1.0) == 2);
    assert(rdp_scroll_rotation_to_pixels(-5, 1.0) == -5);
    assert(rdp_scroll_rotation_to_pixels(3, 1.5) == 5);
    assert(rdp_scroll_rotation_to_pixels(1, 0.25) == 1);
    assert(rdp_scroll_rotation_to_pixels(-1, 0.25) == -1);
    assert(rdp_scroll_rotation_to_pixels(511, 8.0) == 4088);
    assert(rdp_scroll_rotation_to_pixels(512, 8.0) == 4096);
    assert(rdp_scroll_rotation_to_pixels(-512, 8.0) == -4096);
    assert(rdp_scroll_rotation_to_pixels(7, NAN) == 7);

    /* RDP and Quartz define opposite positive directions for horizontal
     * scrolling; vertical conversion above deliberately remains unchanged. */
    assert(rdp_scroll_rotation_to_horizontal_pixels(2, 1.0) == -2);
    assert(rdp_scroll_rotation_to_horizontal_pixels(-5, 1.0) == 5);
    assert(rdp_scroll_rotation_to_horizontal_pixels(3, 1.5) == -5);
    assert(rdp_scroll_rotation_to_horizontal_pixels(-512, 8.0) == 4096);

    puts("scroll input tests passed");
    return 0;
}
