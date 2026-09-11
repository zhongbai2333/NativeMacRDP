#include "input/RDPCursorPositionPolicy.h"

#include <string.h>

#define RDP_POINTER_WHEEL_MASK  0x0600u
#define RDP_POINTER_BUTTON_MASK 0x7000u

RDPCursorPositionEchoMode rdp_cursor_position_echo_mode(const char *value) {
    if (!value || !*value || strcmp(value, "buttons") == 0)
        return RDPCursorPositionEchoButtons;
    if (strcmp(value, "all") == 0)
        return RDPCursorPositionEchoAll;
    if (strcmp(value, "off") == 0)
        return RDPCursorPositionEchoOff;
    return RDPCursorPositionEchoButtons;
}

const char *rdp_cursor_position_echo_mode_name(
        RDPCursorPositionEchoMode mode) {
    switch (mode) {
        case RDPCursorPositionEchoAll: return "all";
        case RDPCursorPositionEchoOff: return "off";
        case RDPCursorPositionEchoButtons:
        default: return "buttons";
    }
}

bool rdp_cursor_should_echo_position(RDPCursorPositionEchoMode mode,
                                     uint16_t flags,
                                     bool extendedMouse) {
    if (mode == RDPCursorPositionEchoOff)
        return false;
    if (!extendedMouse && (flags & RDP_POINTER_WHEEL_MASK) != 0)
        return false;
    if (mode == RDPCursorPositionEchoAll)
        return true;
    return extendedMouse || (flags & RDP_POINTER_BUTTON_MASK) != 0;
}
