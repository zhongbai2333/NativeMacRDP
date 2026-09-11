#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    RDPCursorPositionEchoButtons = 0,
    RDPCursorPositionEchoAll,
    RDPCursorPositionEchoOff,
} RDPCursorPositionEchoMode;

/* Parse RDP_CURSOR_POSITION_ECHO. Unknown and empty values use the safe
 * desktop/touch compromise: echo button coordinates, but not motion. */
RDPCursorPositionEchoMode rdp_cursor_position_echo_mode(const char *value);
const char *rdp_cursor_position_echo_mode_name(
    RDPCursorPositionEchoMode mode);

/* Standard desktop clients already move their cursor locally. Re-sending every
 * input coordinate as a server Pointer Position Update makes a WAN client obey
 * stale, round-tripped coordinates. In buttons mode only clicks/taps are
 * synchronized; extended mouse PDUs are button-only events. */
bool rdp_cursor_should_echo_position(RDPCursorPositionEchoMode mode,
                                     uint16_t flags,
                                     bool extendedMouse);
