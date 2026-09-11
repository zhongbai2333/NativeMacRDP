#import "input/InputInjector.h"
#import "input/RDPScroll.h"
#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <math.h>
#import <stdlib.h>
#import <syslog.h>
#define RDP_LOG_COMPONENT "input"
#include "logging/RDPLog.h"

/* RDP scan code → macOS virtual key code mapping (subset, covering common keys).
   Full table follows USB HID Usage Tables §10 and Mac OS X keycodes. */
static const uint16_t kScanToVK[256] = {
    [0x01] = 53,  /* Esc */
    [0x02] = 18,  /* 1 */  [0x03] = 19,  /* 2 */  [0x04] = 20,  /* 3 */
    [0x05] = 21,  /* 4 */  [0x06] = 23,  /* 5 */  [0x07] = 22,  /* 6 */
    [0x08] = 26,  /* 7 */  [0x09] = 28,  /* 8 */  [0x0A] = 25,  /* 9 */
    [0x0B] = 29,  /* 0 */  [0x0C] = 27,  /* - */  [0x0D] = 24,  /* = */
    [0x0E] = 51,  /* BS */
    [0x0F] = 48,  /* Tab */
    [0x10] = 12,  /* Q */  [0x11] = 13,  /* W */  [0x12] = 14,  /* E */
    [0x13] = 15,  /* R */  [0x14] = 17,  /* T */  [0x15] = 16,  /* Y */
    [0x16] = 32,  /* U */  [0x17] = 34,  /* I */  [0x18] = 31,  /* O */
    [0x19] = 35,  /* P */  [0x1A] = 33,  /* [ */  [0x1B] = 30,  /* ] */
    [0x1C] = 36,  /* Return */
    [0x1D] = 59,  /* LCtrl */
    [0x1E] = 0,   /* A */  [0x1F] = 1,   /* S */  [0x20] = 2,   /* D */
    [0x21] = 3,   /* F */  [0x22] = 5,   /* G */  [0x23] = 4,   /* H */
    [0x24] = 38,  /* J */  [0x25] = 40,  /* K */  [0x26] = 37,  /* L */
    [0x27] = 41,  /* ; */  [0x28] = 39,  /* ' */  [0x29] = 50,  /* ` */
    [0x2A] = 56,  /* LShift */
    [0x2B] = 42,  /* \ */
    [0x2C] = 6,   /* Z */  [0x2D] = 7,   /* X */  [0x2E] = 8,   /* C */
    [0x2F] = 9,   /* V */  [0x30] = 11,  /* B */  [0x31] = 45,  /* N */
    [0x32] = 46,  /* M */  [0x33] = 43,  /* , */  [0x34] = 47,  /* . */
    [0x35] = 44,  /* / */
    [0x36] = 60,  /* RShift */
    [0x37] = 67,  /* KP* */
    [0x38] = 58,  /* LAlt */
    [0x39] = 49,  /* Space */
    [0x3A] = 57,  /* CapsLk */
    [0x3B] = 122, /* F1 */  [0x3C] = 120, /* F2 */  [0x3D] = 99, /* F3 */
    [0x3E] = 118, /* F4 */  [0x3F] = 96,  /* F5 */  [0x40] = 97, /* F6 */
    [0x41] = 98,  /* F7 */  [0x42] = 100, /* F8 */  [0x43] = 101,/* F9 */
    [0x44] = 109, /* F10 */ [0x57] = 103, /* F11 */ [0x58] = 111,/* F12 */
    [0x47] = 71,  /* KP7/Home */
    [0x48] = 126, /* Up */
    [0x4B] = 123, /* Left */
    [0x4D] = 124, /* Right */
    [0x50] = 125, /* Down */
    [0x52] = 114, /* Ins */
    [0x53] = 117, /* Del */
    [0x4F] = 119, /* End */
    [0x49] = 116, /* PgUp */
    [0x51] = 121, /* PgDn */
};

/* Extended scan codes (prefixed 0xE0 in RDP) → macOS VK */
static const uint16_t kExtScanToVK[256] = {
    [0x1C] = 76,  /* KP Enter */
    [0x1D] = 62,  /* RCtrl */
    [0x35] = 75,  /* KP/ */
    [0x38] = 61,  /* RAlt */
    [0x47] = 115, /* Home */
    [0x48] = 126, /* Up */
    [0x49] = 116, /* PgUp */
    [0x4B] = 123, /* Left */
    [0x4D] = 124, /* Right */
    [0x4F] = 119, /* End */
    [0x50] = 125, /* Down */
    [0x51] = 121, /* PgDn */
    [0x52] = 114, /* Insert */
    [0x53] = 117, /* Delete */
    [0x5B] = 55,  /* LCmd */
    [0x5C] = 54,  /* RCmd */
};

@interface InputInjector ()
@property (nonatomic, assign) CGDirectDisplayID displayID;
@property (nonatomic, assign) uint32_t srcW;   /* RDP desktop width  (pointer coord space) */
@property (nonatomic, assign) uint32_t srcH;   /* RDP desktop height */
/* Button state — needed to emit MouseDragged (not MouseMoved) while a button
 * is held, otherwise drags / text selection / window moves don't work. */
@property (nonatomic, assign) BOOL leftDown;
@property (nonatomic, assign) BOOL rightDown;
@property (nonatomic, assign) BOOL middleDown;
/* RDP Unicode input arrives as individual UTF-16 code units. Posting one Quartz
 * key-down/up pair per unit can overwhelm the session event queue during fast
 * software-keyboard input. Buffer a short burst and submit it as one committed
 * text event; a private serial queue preserves ordering and surrogate pairs. */
@property (nonatomic, strong) dispatch_queue_t unicodeQueue;
@property (nonatomic, strong) dispatch_source_t unicodeFlushTimer;
@property (nonatomic, strong) NSMutableString *unicodeBuffer;
/* Windows App sends high-resolution wheel deltas, often batched into the same
 * millisecond after a network delay. Preserve their signed magnitude but emit
 * one pixel-scroll event per short batch so Quartz cannot build a stale queue. */
@property (nonatomic, strong) dispatch_queue_t scrollQueue;
@property (nonatomic, strong) dispatch_source_t scrollFlushTimer;
@property (nonatomic, assign) int64_t pendingScrollVertical;
@property (nonatomic, assign) int64_t pendingScrollHorizontal;
@property (nonatomic, assign) BOOL scrollFlushScheduled;
@property (nonatomic, assign) double scrollPixelScale;
/* Mobile RDP clients can lose a modifier key-up while focus moves between the
 * remote canvas and their software keyboard. Track modifiers inside this RDP
 * session and apply them atomically as flags on non-modifier key events; never
 * leave a corresponding standalone modifier held in Quartz. */
@property (nonatomic, assign) uint32_t remoteModifierMask;
@end

enum {
    RDPModifierLeftControl  = 1u << 0,
    RDPModifierRightControl = 1u << 1,
    RDPModifierLeftShift    = 1u << 2,
    RDPModifierRightShift   = 1u << 3,
    RDPModifierLeftOption   = 1u << 4,
    RDPModifierRightOption  = 1u << 5,
    RDPModifierLeftCommand  = 1u << 6,
    RDPModifierRightCommand = 1u << 7,
};

typedef struct {
    uint32_t bit;
    CGKeyCode keyCode;
} RDPModifierKey;

static const RDPModifierKey kModifierKeys[] = {
    { RDPModifierLeftControl,  59 },
    { RDPModifierRightControl, 62 },
    { RDPModifierLeftShift,    56 },
    { RDPModifierRightShift,   60 },
    { RDPModifierLeftOption,   58 },
    { RDPModifierRightOption,  61 },
    { RDPModifierLeftCommand,  55 },
    { RDPModifierRightCommand, 54 },
};

static CGEventFlags RDPEventFlagsForModifierMask(uint32_t mask) {
    CGEventFlags flags = 0;
    if (mask & (RDPModifierLeftControl | RDPModifierRightControl))
        flags |= kCGEventFlagMaskControl;
    if (mask & (RDPModifierLeftShift | RDPModifierRightShift))
        flags |= kCGEventFlagMaskShift;
    if (mask & (RDPModifierLeftOption | RDPModifierRightOption))
        flags |= kCGEventFlagMaskAlternate;
    if (mask & (RDPModifierLeftCommand | RDPModifierRightCommand))
        flags |= kCGEventFlagMaskCommand;
    return flags;
}

static double RDPScrollPixelScaleFromEnvironment(void) {
    const char *raw = getenv("RDP_SCROLL_PIXEL_SCALE");
    if (!raw || !*raw) return 1.0;

    char *end = NULL;
    const double value = strtod(raw, &end);
    if (!end || end == raw || *end != '\0' || !isfinite(value) ||
        value < 0.25 || value > 8.0)
        return 1.0;
    return value;
}

static int32_t RDPClampPendingScroll(int64_t value) {
    if (value > 4096) return 4096;
    if (value < -4096) return -4096;
    return (int32_t)value;
}

static uint32_t RDPModifierMaskForScanCode(uint16_t code, BOOL extended) {
    if (code == 0x1D)
        return extended ? RDPModifierRightControl : RDPModifierLeftControl;
    if (code == 0x2A && !extended) return RDPModifierLeftShift;
    if (code == 0x36 && !extended) return RDPModifierRightShift;
    if (code == 0x38)
        return extended ? RDPModifierRightOption : RDPModifierLeftOption;
    if (code == 0x5B && extended) return RDPModifierLeftCommand;
    if (code == 0x5C && extended) return RDPModifierRightCommand;
    return 0u;
}

@implementation InputInjector

- (instancetype)initWithDisplayID:(CGDirectDisplayID)did
                      sourceWidth:(uint32_t)sourceWidth
                     sourceHeight:(uint32_t)sourceHeight {
    if ((self = [super init])) {
        _displayID = did;
        _srcW = sourceWidth;
        _srcH = sourceHeight;
        _unicodeQueue = dispatch_queue_create("com.macosrdp.unicode-input",
                                              DISPATCH_QUEUE_SERIAL);
        _unicodeBuffer = [[NSMutableString alloc] init];
        _unicodeFlushTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,
                                                     0, 0, _unicodeQueue);
        __weak typeof(self) weak = self;
        dispatch_source_set_event_handler(_unicodeFlushTimer, ^{
            [weak flushUnicodeBuffer];
        });
        /* Start disabled; each arriving code unit arms a one-shot deadline. */
        dispatch_source_set_timer(_unicodeFlushTimer, DISPATCH_TIME_FOREVER,
                                  DISPATCH_TIME_FOREVER, 0);
        dispatch_resume(_unicodeFlushTimer);

        _scrollPixelScale = RDPScrollPixelScaleFromEnvironment();
        _scrollQueue = dispatch_queue_create("com.macosrdp.scroll-input",
                                             DISPATCH_QUEUE_SERIAL);
        _scrollFlushTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,
                                                    0, 0, _scrollQueue);
        __weak typeof(self) weakSelf = self;
        dispatch_source_set_event_handler(_scrollFlushTimer, ^{
            [weakSelf flushPendingScroll];
        });
        dispatch_source_set_timer(_scrollFlushTimer, DISPATCH_TIME_FOREVER,
                                  DISPATCH_TIME_FOREVER, 0);
        dispatch_resume(_scrollFlushTimer);
        rdp_info("pixel scroll input: scale=%.2f coalesce=4ms",
                 _scrollPixelScale);
        /* Prompt for Accessibility (required for CGEventPost) and register the
         * binary in the Privacy list. In the GUI session this pops the system
         * dialog the first time; thereafter it just reports the trust state. */
        NSDictionary *opts = @{ (__bridge id)kAXTrustedCheckOptionPrompt: @YES };
        if (!AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)opts))
            rdp_error("Accessibility not granted — input injection will not work "
                      "until enabled (grant the prompt or System Settings > Privacy "
                      "& Security > Accessibility)");

        /* Recover from a daemon that may have exited between modifier key-down
         * and key-up. Do this once when the injector is created. Repeating
         * synthetic key-up events for every modifier at each focus/synchronize
         * boundary can activate applications that bind a modifier by itself
         * (for example WeChat's hold-right-Option voice shortcut). */
        [self releaseAllModifiers];
    }
    return self;
}

- (CGKeyCode)keyCodeForScanCode:(uint16_t)code extended:(BOOL)ext {
    const uint16_t *table = ext ? kExtScanToVK : kScanToVK;
    if (code >= 256) return 0xFFFF;
    uint16_t vk = table[code];
    /* The sparse tables are zero-filled, but zero is also the valid macOS key
     * code for A. Never turn an unknown RDP scan code into a phantom A. */
    if (vk == 0 && !(code == 0x1E && !ext)) return 0xFFFF;
    return (CGKeyCode)vk;
}

- (void)releaseTrackedModifiers {
    uint32_t mask = _remoteModifierMask;
    if (!mask) return;
    _remoteModifierMask = 0u;
    /* Modifier downs are represented as flags on the associated non-modifier
     * key event, never as a persistent Quartz key state. Clearing our mask is
     * therefore sufficient and cannot fire modifier-only app shortcuts. */
    rdp_info("cleared stale remote keyboard modifiers mask=0x%02x", mask);
}

- (void)releaseAllModifiers {
    _remoteModifierMask = 0u;
    /* One process-lifetime migration cleanup releases state potentially left
     * by an older daemon that posted physical modifier events. Repeating these
     * key-ups on every reconnect can itself trigger apps with modifier-only
     * shortcuts (notably hold-right-Option voice input). */
    static dispatch_once_t inheritedModifierCleanup;
    dispatch_once(&inheritedModifierCleanup, ^{
        for (size_t i = 0;
             i < sizeof(kModifierKeys) / sizeof(kModifierKeys[0]); i++) {
            CGEventRef event = CGEventCreateKeyboardEvent(
                NULL, kModifierKeys[i].keyCode, false);
            if (!event) continue;
            CGEventPost(kCGSessionEventTap, event);
            CFRelease(event);
        }
        rdp_info("reset inherited keyboard modifier state");
    });
}

- (void)resetKeyboardState {
    dispatch_sync(_unicodeQueue, ^{ [self flushUnicodeBuffer]; });
    /* Focus and synchronize PDUs are normal during a live session. Release only
     * modifiers this connection actually pressed; the one-time inherited-state
     * recovery is handled during initialization above. */
    [self releaseTrackedModifiers];
}

- (void)injectKeyEvent:(uint16_t)flags scanCode:(uint16_t)code {
    /* Backspace/Return/arrows/modifiers are scan-code events even in Unicode
     * mode. Commit pending text first so these events cannot overtake it. */
    dispatch_sync(_unicodeQueue, ^{ [self flushUnicodeBuffer]; });

    BOOL isRelease = (flags & RDP_KBD_RELEASE) != 0;
    BOOL isExtended = (flags & RDP_KBD_EXTENDED) != 0;
    CGKeyCode vk = [self keyCodeForScanCode:code extended:isExtended];
    if (vk == 0xFFFF) return;

    uint32_t modifier = RDPModifierMaskForScanCode(code, isExtended);
    if (modifier) {
        if (isRelease)
            _remoteModifierMask &= ~modifier;
        else
            _remoteModifierMask |= modifier;
    }
    if (modifier || code == 0x12 || code == 0x20 ||
        code == 0x2E || code == 0x2F) {
        rdp_info("keyboard inject: scan=0x%02x extended=%d release=%d "
                 "mac-vk=%u modifiers=0x%02x",
                 code, isExtended ? 1 : 0, isRelease ? 1 : 0,
                 (unsigned)vk, _remoteModifierMask);
    }

    /* Keep remote modifiers session-local. Posting an independent right-Option
     * down can activate macOS/WeChat voice input and steal focus before the
     * corresponding key-up arrives. A non-modifier key carrying the same Quartz
     * flags preserves ordinary Ctrl/Shift/Option/Command shortcuts without any
     * global modifier state that can become stuck. */
    if (modifier) return;

    CGEventRef event = CGEventCreateKeyboardEvent(NULL, vk, !isRelease);
    if (!event) return;
    CGEventSetFlags(event, RDPEventFlagsForModifierMask(_remoteModifierMask));

    /* Post to the session event stream so it reaches the frontmost app. */
    CGEventPost(kCGSessionEventTap, event);
    CFRelease(event);
}

- (void)postUnicodeCharacters:(const UniChar *)characters length:(size_t)length {
    if (!characters || length == 0) return;

    CGEventRef down = CGEventCreateKeyboardEvent(NULL, 0, true);
    CGEventRef up = CGEventCreateKeyboardEvent(NULL, 0, false);
    if (!down || !up) {
        if (down) CFRelease(down);
        if (up) CFRelease(up);
        return;
    }

    /* Unicode PDUs are already committed text. Do not let a modifier flag left
     * in Quartz's combined session state reinterpret D/E as Control commands;
     * real shortcuts continue to use the scan-code path. */
    CGEventSetFlags(down, 0);
    CGEventSetFlags(up, 0);
    CGEventKeyboardSetUnicodeString(down, length, characters);
    CGEventKeyboardSetUnicodeString(up, length, characters);
    CGEventPost(kCGSessionEventTap, down);
    CGEventPost(kCGSessionEventTap, up);
    CFRelease(down);
    CFRelease(up);
}

- (void)flushUnicodeBuffer {
    /* unicodeQueue only. Quartz accepts a string on one keyboard event; use
     * modest chunks to stay compatible with text fields that cap event text. */
    if (_unicodeBuffer.length == 0) return;

    NSString *text = [_unicodeBuffer copy];
    [_unicodeBuffer setString:@""];
    dispatch_source_set_timer(_unicodeFlushTimer, DISPATCH_TIME_FOREVER,
                              DISPATCH_TIME_FOREVER, 0);

    enum { kMaxUnitsPerEvent = 20 };
    UniChar units[kMaxUnitsPerEvent];
    for (NSUInteger offset = 0; offset < text.length; offset += kMaxUnitsPerEvent) {
        NSUInteger count = MIN(kMaxUnitsPerEvent, text.length - offset);
        [text getCharacters:units range:NSMakeRange(offset, count)];
        [self postUnicodeCharacters:units length:count];
    }
}

- (void)injectUnicodeKeyEvent:(uint16_t)flags codeUnit:(uint16_t)codeUnit {
    /* Unicode RDP input carries UTF-16 code units. Text is emitted on key-down;
     * the matching release PDU only terminates the logical key. */
    if (flags & RDP_KBD_RELEASE) return;

    if (codeUnit == 'd' || codeUnit == 'D' || codeUnit == 'e' ||
        codeUnit == 'E' || codeUnit == 'c' || codeUnit == 'C' ||
        codeUnit == 'v' || codeUnit == 'V') {
        rdp_info("keyboard inject: unicode=U+%04X modifiers-before=0x%02x",
                 codeUnit, _remoteModifierMask);
    }

    /* Unicode PDUs are committed text; keyboard shortcuts arrive as scan codes.
     * A modifier still down at this boundary is stale, so clear it before Quartz
     * interprets D/E as Control commands. */
    [self releaseTrackedModifiers];

    UniChar unit = (UniChar)codeUnit;
    dispatch_async(_unicodeQueue, ^{
        NSString *piece = [NSString stringWithCharacters:&unit length:1];
        [self.unicodeBuffer appendString:piece];

        /* 12 ms groups a burst/IME commit without adding perceptible latency.
         * Force a flush at 20 UTF-16 units so held/repeated input stays bounded. */
        if (self.unicodeBuffer.length >= 20) {
            [self flushUnicodeBuffer];
        } else {
            dispatch_source_set_timer(
                self.unicodeFlushTimer,
                dispatch_time(DISPATCH_TIME_NOW, 12 * NSEC_PER_MSEC),
                DISPATCH_TIME_FOREVER, 2 * NSEC_PER_MSEC);
        }
    });
}

- (void)dealloc {
    if (_unicodeFlushTimer) dispatch_source_cancel(_unicodeFlushTimer);
    if (_scrollFlushTimer) dispatch_source_cancel(_scrollFlushTimer);
}

- (void)injectMouseEvent:(uint16_t)flags x:(uint16_t)x y:(uint16_t)y {
    /* The client sends pointer coords in the RDP desktop space (0..srcW, 0..srcH).
     * The capture preserves the Mac's aspect ratio inside that surface, so the Mac
     * image occupies a CENTERED sub-rectangle with letterbox/pillarbox bars when the
     * client and Mac aspect ratios differ. Map the pointer into that content rect
     * (not the whole surface), then to the Mac display's point bounds — otherwise the
     * bars throw off the cursor position. */
    CGRect bounds = CGDisplayBounds(_displayID);
    double macAspect  = bounds.size.width / bounds.size.height;
    double surfAspect = (_srcH > 0) ? (double)_srcW / (double)_srcH : macAspect;
    double contentW, contentH, offX, offY;
    if (macAspect < surfAspect) {            /* pillarbox: content fits the height */
        contentH = _srcH; contentW = (double)_srcH * macAspect;
        offX = ((double)_srcW - contentW) / 2.0; offY = 0;
    } else {                                  /* letterbox: content fits the width */
        contentW = _srcW; contentH = (double)_srcW / macAspect;
        offX = 0; offY = ((double)_srcH - contentH) / 2.0;
    }
    double fx = (contentW > 0) ? ((double)x - offX) / contentW : 0;  /* 0..1 in content */
    double fy = (contentH > 0) ? ((double)y - offY) / contentH : 0;
    if (fx < 0) fx = 0; else if (fx > 1) fx = 1;
    if (fy < 0) fy = 0; else if (fy > 1) fy = 1;
    CGPoint pos = CGPointMake(bounds.origin.x + fx * bounds.size.width,
                              bounds.origin.y + fy * bounds.size.height);

    BOOL down = (flags & RDP_PTR_DOWN) != 0;
    CGEventType type;
    CGMouseButton button;

    if (flags & RDP_PTR_BUTTON1) {
        button = kCGMouseButtonLeft;
        type = down ? kCGEventLeftMouseDown : kCGEventLeftMouseUp;
        _leftDown = down;
    } else if (flags & RDP_PTR_BUTTON2) {
        button = kCGMouseButtonRight;
        type = down ? kCGEventRightMouseDown : kCGEventRightMouseUp;
        _rightDown = down;
    } else if (flags & RDP_PTR_BUTTON3) {
        button = kCGMouseButtonCenter;
        type = down ? kCGEventOtherMouseDown : kCGEventOtherMouseUp;
        _middleDown = down;
    } else if (flags & RDP_PTR_MOVE) {
        /* A move with a button held is a drag — macOS needs the dragged event
         * type or the gesture (selection, window move) is dropped. */
        if (_leftDown)        { type = kCGEventLeftMouseDragged;  button = kCGMouseButtonLeft; }
        else if (_rightDown)  { type = kCGEventRightMouseDragged; button = kCGMouseButtonRight; }
        else if (_middleDown) { type = kCGEventOtherMouseDragged; button = kCGMouseButtonCenter; }
        else                  { type = kCGEventMouseMoved;        button = kCGMouseButtonLeft; }
    } else {
        return; /* nothing actionable */
    }

    CGEventRef event = CGEventCreateMouseEvent(NULL, type, pos, button);
    if (!event) return;
    CGEventPost(kCGSessionEventTap, event);
    CFRelease(event);
}

- (void)flushPendingScroll {
    /* scrollQueue only. Clamp one Quartz event rather than each input PDU; this
     * retains speed across a burst without allowing a pathological packet run
     * to inject an unbounded jump. */
    const int32_t vertical = RDPClampPendingScroll(_pendingScrollVertical);
    const int32_t horizontal = RDPClampPendingScroll(_pendingScrollHorizontal);
    _pendingScrollVertical = 0;
    _pendingScrollHorizontal = 0;
    _scrollFlushScheduled = NO;
    dispatch_source_set_timer(_scrollFlushTimer, DISPATCH_TIME_FOREVER,
                              DISPATCH_TIME_FOREVER, 0);
    if (vertical == 0 && horizontal == 0) return;

    CGEventRef event = CGEventCreateScrollWheelEvent(
        NULL, kCGScrollEventUnitPixel, 2, vertical, horizontal);
    if (!event) return;
    CGEventSetIntegerValueField(event, kCGScrollWheelEventIsContinuous, 1);
    CGEventSetIntegerValueField(event, kCGScrollWheelEventScrollCount, 1);
    CGEventPost(kCGSessionEventTap, event);
    CFRelease(event);
    rdp_debug("pixel scroll flush: vertical=%d horizontal=%d",
              vertical, horizontal);
}

- (void)injectMouseWheelEvent:(uint16_t)flags x:(uint16_t)x y:(uint16_t)y {
    (void)x; (void)y;
    const BOOL horizontal = (flags & RDP_PTR_HWHEEL) != 0;
    const int32_t rotation = rdp_scroll_decode_rotation(flags);
    const int32_t pixels = horizontal
        ? rdp_scroll_rotation_to_horizontal_pixels(rotation,
                                                   _scrollPixelScale)
        : rdp_scroll_rotation_to_pixels(rotation, _scrollPixelScale);
    if (pixels == 0) return;

    dispatch_async(_scrollQueue, ^{
        if (horizontal)
            self.pendingScrollHorizontal += pixels;
        else
            self.pendingScrollVertical += pixels;

        if (!self.scrollFlushScheduled) {
            self.scrollFlushScheduled = YES;
            dispatch_source_set_timer(
                self.scrollFlushTimer,
                dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_MSEC),
                DISPATCH_TIME_FOREVER, NSEC_PER_MSEC);
        }
    });
}

@end
