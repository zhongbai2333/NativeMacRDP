#include "input/RDPCursorPositionPolicy.h"

#include <assert.h>
#include <stdio.h>

#define PTR_MOVE    0x0800u
#define PTR_DOWN    0x8000u
#define PTR_BUTTON1 0x1000u
#define PTR_WHEEL   0x0200u
#define PTR_HWHEEL  0x0400u

int main(void) {
    assert(rdp_cursor_position_echo_mode(NULL) ==
           RDPCursorPositionEchoButtons);
    assert(rdp_cursor_position_echo_mode("") ==
           RDPCursorPositionEchoButtons);
    assert(rdp_cursor_position_echo_mode("buttons") ==
           RDPCursorPositionEchoButtons);
    assert(rdp_cursor_position_echo_mode("all") ==
           RDPCursorPositionEchoAll);
    assert(rdp_cursor_position_echo_mode("off") ==
           RDPCursorPositionEchoOff);
    assert(rdp_cursor_position_echo_mode("invalid") ==
           RDPCursorPositionEchoButtons);

    assert(!rdp_cursor_should_echo_position(RDPCursorPositionEchoButtons,
                                            PTR_MOVE, false));
    assert(rdp_cursor_should_echo_position(RDPCursorPositionEchoButtons,
                                           PTR_BUTTON1 | PTR_DOWN, false));
    assert(rdp_cursor_should_echo_position(RDPCursorPositionEchoButtons,
                                           PTR_BUTTON1, false));
    assert(!rdp_cursor_should_echo_position(RDPCursorPositionEchoButtons,
                                            PTR_WHEEL, false));
    assert(!rdp_cursor_should_echo_position(RDPCursorPositionEchoButtons,
                                            PTR_HWHEEL, false));
    assert(rdp_cursor_should_echo_position(RDPCursorPositionEchoButtons,
                                           0x0001u, true));

    assert(rdp_cursor_should_echo_position(RDPCursorPositionEchoAll,
                                           PTR_MOVE, false));
    assert(!rdp_cursor_should_echo_position(RDPCursorPositionEchoAll,
                                            PTR_WHEEL, false));
    assert(rdp_cursor_should_echo_position(RDPCursorPositionEchoAll,
                                           0x0001u, true));

    assert(!rdp_cursor_should_echo_position(RDPCursorPositionEchoOff,
                                            PTR_BUTTON1 | PTR_DOWN, false));
    assert(!rdp_cursor_should_echo_position(RDPCursorPositionEchoOff,
                                            0x0001u, true));

    puts("cursor position policy tests passed");
    return 0;
}
