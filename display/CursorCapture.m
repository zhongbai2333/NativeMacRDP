#import "display/CursorCapture.h"
#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>

#define RDP_LOG_COMPONENT "cursor"
#include "logging/RDPLog.h"

/*
 * HEADLESS CURSOR CAPTURE (read before changing the timer or read path)
 * ---------------------------------------------------------------------
 * This daemon has NO running main run loop: the main thread blocks forever in
 * kevent() (see daemon/main.m), and there is no NSApplication. So:
 *   - We CANNOT drive an NSTimer on the main run loop (it would never fire).
 *     Instead we run a dispatch_source timer on a dedicated background serial
 *     queue, mirroring how DisplayControl.m drives work off the main thread.
 *   - We CANNOT rely on NSCursor.currentSystemCursor: it is AppKit/main-thread-
 *     affine and unreliable in a headless LaunchAgent. Instead we read the live
 *     on-screen system cursor via the private CoreGraphics (CGS) cursor API,
 *     which answers from any thread without AppKit. NSCursor remains only as a
 *     last-resort fallback if CGS yields nothing.
 */

/* ── Private CoreGraphics (CGS / SkyLight) cursor API ─────────────────────────
 * These are private symbols (no public header) used to read the actual on-screen
 * system cursor from a daemon. Signatures cross-checked against the community
 * CGSInternal headers; stable across macOS releases including 26. */
typedef int CGSConnectionID;
extern CGSConnectionID CGSMainConnectionID(void);
/* Bumps whenever the system cursor changes — a cheap poll-time change detector. */
extern int CGSCurrentCursorSeed(void);
/* Byte size of the active cursor's bitmap, for allocating the data buffer. */
extern CGError CGSGetGlobalCursorDataSize(CGSConnectionID cid, size_t *outSize);
/* Full cursor read: bitmap bytes + layout + on-screen rect + hotspot.
 *   outData            caller-provided buffer of CGSGetGlobalCursorDataSize bytes
 *   outDataSize        bytes actually written
 *   outRowBytes        source stride
 *   outRect            cursor rect (size = bitmap dimensions in pixels)
 *   outHotSpot         hotspot in cursor-local points (top-left origin)
 *   outDepth           bits per pixel (typically 32)
 *   outComponents      components per pixel (typically 4 = RGBA/ARGB)
 *   outBitsPerComponent typically 8 */
extern CGError CGSGetGlobalCursorData(CGSConnectionID cid, void *outData,
                                      int *outDataSize, int *outRowBytes,
                                      CGRect *outRect, CGPoint *outHotSpot,
                                      int *outDepth, int *outComponents,
                                      int *outBitsPerComponent);

/* Cap the bitmap we send. Most macOS cursors are 32x32 (or 64x64 at 2x).
 * RDP color/large pointers tolerate large sizes, but mstsc renders best with
 * a modest cap and it keeps the bytestream small. */
static const uint32_t kMaxCursorDim = 96;

/* ~12 Hz: fast enough that a shape change (I-beam, resize, hand) feels
 * instantaneous without burning CPU rasterizing the cursor every frame. */
static const uint64_t kPollIntervalNanos = (uint64_t)(NSEC_PER_SEC / 12);

@interface CursorCapture ()
@property (nonatomic, strong, nullable) dispatch_queue_t queue;
@property (nonatomic, strong, nullable) dispatch_source_t timer;
@property (nonatomic, assign) uint64_t lastHash;   /* 0 == nothing sent yet */
@property (nonatomic, assign) int      lastSeed;    /* CGS cursor seed last read */
@property (nonatomic, assign) BOOL     haveSeed;
@end

@implementation CursorCapture

- (void)start {
    if (_timer) return;
    _lastHash = 0;
    _haveSeed = NO;

    /* Dedicated background serial queue — NOT the main queue, which never
     * drains in this daemon (see header note). */
    _queue = dispatch_queue_create("com.macos-rdp.cursor-capture",
                                    DISPATCH_QUEUE_SERIAL);

    __weak typeof(self) weak = self;
    dispatch_source_t t =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    /* RDPSession starts us from inside FreeRDP's Activate callback. Do not send
     * an output PDU until that callback has returned and Confirm Active handling
     * is fully complete; early pointer definitions are silently ignored by some
     * Windows App builds. */
    dispatch_source_set_timer(t,
                              dispatch_time(DISPATCH_TIME_NOW,
                                            750 * NSEC_PER_MSEC),
                              kPollIntervalNanos,
                              kPollIntervalNanos / 4);              /* leeway */
    dispatch_source_set_event_handler(t, ^{ [weak poll]; });
    _timer = t;
    dispatch_resume(t);

    rdp_verbose("cursor capture started (~12 Hz, dispatch timer, CGS live cursor)");
}

- (void)stop {
    if (_timer) {
        dispatch_source_cancel(_timer);
        _timer = nil;
    }
    _queue = nil;
    rdp_verbose("cursor capture stopped");
}

/* FNV-1a over the bitmap bytes + dimensions + hotspot, to detect shape changes. */
static uint64_t fnv1a(const uint8_t *p, size_t n, uint64_t seed) {
    uint64_t h = seed ? seed : 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

/* Windows App renders the captured macOS arrow correctly, but several native
 * center-hotspot bitmaps corrupt when represented by classic RDP AND/XOR masks.
 * Earlier builds replaced every non-arrow with one crosshair, which made an
 * I-beam look like a crosshair even though capture had identified the shape
 * correctly. Classify the original alpha silhouette and generate a stable,
 * high-contrast compatibility cursor of the same semantic family instead. */
typedef NS_ENUM(uint8_t, RDPCompatibilityCursorKind) {
    RDPCompatibilityCursorNative = 0,
    RDPCompatibilityCursorIBeam,
    RDPCompatibilityCursorCrosshair,
    RDPCompatibilityCursorResizeLeftRight,
    RDPCompatibilityCursorResizeUpDown,
    RDPCompatibilityCursorHand,
};

static const char *compatibilityCursorName(RDPCompatibilityCursorKind kind) {
    switch (kind) {
        case RDPCompatibilityCursorIBeam:           return "I-beam";
        case RDPCompatibilityCursorCrosshair:       return "crosshair";
        case RDPCompatibilityCursorResizeLeftRight: return "left-right resize";
        case RDPCompatibilityCursorResizeUpDown:    return "up-down resize";
        case RDPCompatibilityCursorHand:            return "hand";
        default:                                    return "native";
    }
}

static RDPCompatibilityCursorKind classifyCompatibilityCursor(
        const uint8_t *bgra, uint32_t w, uint32_t h,
        uint16_t hotX, uint16_t hotY) {
    if (!bgra || w == 0 || h == 0) return RDPCompatibilityCursorCrosshair;

    uint32_t minX = w, minY = h, maxX = 0, maxY = 0, opaque = 0;
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++) {
            if (bgra[((size_t)y * w + x) * 4u + 3u] < 32u) continue;
            opaque++;
            if (x < minX) minX = x;
            if (x > maxX) maxX = x;
            if (y < minY) minY = y;
            if (y > maxY) maxY = y;
        }
    }
    if (opaque == 0) return RDPCompatibilityCursorCrosshair;

    const uint32_t boxW = maxX - minX + 1u;
    const uint32_t boxH = maxY - minY + 1u;
    const uint32_t densityPermille =
        (uint32_t)(((uint64_t)opaque * 1000u) / ((uint64_t)boxW * boxH));
    uint32_t emptyInteriorRows = 0;
    for (uint32_t y = minY; y <= maxY; y++) {
        BOOL any = NO;
        for (uint32_t x = minX; x <= maxX; x++) {
            if (bgra[((size_t)y * w + x) * 4u + 3u] >= 32u) {
                any = YES;
                break;
            }
        }
        if (!any) emptyInteriorRows++;
    }
    const BOOL centered =
        abs((int)hotX - (int)(w / 2u)) <= (int)(w / 4u + 1u) &&
        abs((int)hotY - (int)(h / 2u)) <= (int)(h / 4u + 1u);

    /* Native arrow on this Mac is 28x40, hot=(5,5), with a narrow diagonal
     * silhouette. Preserve top-left-hotspot cursors so the common arrow remains
     * pixel-perfect and locally rendered by Windows App. */
    if (!centered && h >= w && (uint32_t)hotX * 3u < w &&
        (uint32_t)hotY * 3u < h)
        return RDPCompatibilityCursorNative;

    /* Hardware pointing-hand sample: 32x32, hot=(12,8), bbox 17x21 and 66.7%
     * fill. It is slightly taller than the old aspect-ratio resize threshold,
     * so recognize the upper hotspot / dense silhouette before resize shapes. */
    if (centered &&
        ((uint32_t)hotY * 3u < h ||
         (densityPermille >= 630u &&
          (uint64_t)boxH * 4u < (uint64_t)boxW * 7u)))
        return RDPCompatibilityCursorHand;

    if (centered && (uint64_t)boxW * 5u >= (uint64_t)boxH * 6u)
        return RDPCompatibilityCursorResizeLeftRight;

    /* The live 18x28 up/down cursor consists of two separated arrowheads: its
     * 10x23 alpha bbox has two completely empty middle rows. An I-beam has a
     * continuous vertical stem, so this structural signal is unambiguous even
     * when the resize bitmap is narrower than the standard AppKit artwork. */
    if (centered && emptyInteriorRows > 0u &&
        (uint64_t)boxH * 5u >= (uint64_t)boxW * 6u)
        return RDPCompatibilityCursorResizeUpDown;

    /* Hardware text sample: 23x22, hot=(12,11), alpha bbox 9x20. Require the
     * uninterrupted narrow stem in addition to the tall silhouette. */
    if (centered && emptyInteriorRows == 0u &&
        (uint64_t)boxH * 4u >= (uint64_t)boxW * 7u &&
        densityPermille < 700u)
        return RDPCompatibilityCursorIBeam;

    if (centered && (uint64_t)boxH * 5u >= (uint64_t)boxW * 6u)
        return RDPCompatibilityCursorResizeUpDown;

    /* Crosshairs are sparse, whereas hand cursors have a dense, roughly square
     * silhouette. A generic hand is preferable to silently calling it a cross. */
    if (centered && densityPermille < 600u)
        return RDPCompatibilityCursorCrosshair;
    return RDPCompatibilityCursorHand;
}

static void setCorePixel(uint8_t *core, uint32_t w, uint32_t h,
                         int x, int y) {
    if (x >= 0 && y >= 0 && (uint32_t)x < w && (uint32_t)y < h)
        core[(size_t)y * w + (uint32_t)x] = 1;
}

static uint8_t *copyCompatibilityCursor(RDPCompatibilityCursorKind kind,
                                        uint32_t *outW, uint32_t *outH,
                                        uint16_t *outHotX,
                                        uint16_t *outHotY) {
    uint32_t w = 25, h = 25;
    uint16_t hotX = 12, hotY = 12;
    if (kind == RDPCompatibilityCursorIBeam) {
        w = 17; h = 25; hotX = 8; hotY = 12;
    } else if (kind == RDPCompatibilityCursorResizeLeftRight) {
        w = 25; h = 17; hotX = 12; hotY = 8;
    } else if (kind == RDPCompatibilityCursorResizeUpDown) {
        w = 17; h = 25; hotX = 8; hotY = 12;
    } else if (kind == RDPCompatibilityCursorHand) {
        w = 21; h = 25; hotX = 8; hotY = 2;
    }

    uint8_t *core = calloc((size_t)w * h, 1u);
    uint8_t *pixels = calloc((size_t)w * h, 4u);
    if (!core || !pixels) { free(core); free(pixels); return NULL; }

    if (kind == RDPCompatibilityCursorIBeam) {
        for (int x = 4; x <= 12; x++) {
            setCorePixel(core, w, h, x, 3);
            setCorePixel(core, w, h, x, 21);
        }
        for (int y = 3; y <= 21; y++) setCorePixel(core, w, h, 8, y);
    } else if (kind == RDPCompatibilityCursorResizeLeftRight) {
        for (int x = 3; x <= 21; x++) setCorePixel(core, w, h, x, 8);
        for (int d = 0; d <= 5; d++) {
            setCorePixel(core, w, h, 3 + d, 8 - d);
            setCorePixel(core, w, h, 3 + d, 8 + d);
            setCorePixel(core, w, h, 21 - d, 8 - d);
            setCorePixel(core, w, h, 21 - d, 8 + d);
        }
    } else if (kind == RDPCompatibilityCursorResizeUpDown) {
        for (int y = 3; y <= 21; y++) setCorePixel(core, w, h, 8, y);
        for (int d = 0; d <= 5; d++) {
            setCorePixel(core, w, h, 8 - d, 3 + d);
            setCorePixel(core, w, h, 8 + d, 3 + d);
            setCorePixel(core, w, h, 8 - d, 21 - d);
            setCorePixel(core, w, h, 8 + d, 21 - d);
        }
    } else if (kind == RDPCompatibilityCursorHand) {
        /* One raised finger plus palm/thumb. The exact macOS artwork cannot be
         * represented losslessly by the classic pointer mask, but the semantic
         * shape and hotspot remain unambiguous. */
        for (int y = 2; y <= 15; y++)
            for (int x = 7; x <= 9; x++) setCorePixel(core, w, h, x, y);
        for (int y = 10; y <= 20; y++)
            for (int x = 7; x <= 16; x++) setCorePixel(core, w, h, x, y);
        for (int y = 12; y <= 16; y++)
            for (int x = 4; x <= 7; x++) setCorePixel(core, w, h, x, y);
        for (int y = 8; y <= 13; y++)
            for (int x = 10; x <= 12; x++) setCorePixel(core, w, h, x, y);
        for (int y = 9; y <= 14; y++)
            for (int x = 13; x <= 15; x++) setCorePixel(core, w, h, x, y);
    } else {
        for (int x = 2; x <= 22; x++) setCorePixel(core, w, h, x, 12);
        for (int y = 2; y <= 22; y++) setCorePixel(core, w, h, 12, y);
    }

    /* Render a one-pixel black outline around a white core. All pixels are
     * fully opaque so mstsc never has to interpret semi-transparent edges. */
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++) {
            BOOL nearCore = NO;
            for (int dy = -1; dy <= 1 && !nearCore; dy++) {
                for (int dx = -1; dx <= 1; dx++) {
                    int nx = (int)x + dx, ny = (int)y + dy;
                    if (nx >= 0 && ny >= 0 && (uint32_t)nx < w &&
                        (uint32_t)ny < h && core[(size_t)ny * w + (uint32_t)nx]) {
                        nearCore = YES;
                        break;
                    }
                }
            }
            if (!nearCore) continue;
            uint8_t *p = pixels + ((size_t)y * w + x) * 4u;
            const uint8_t v = core[(size_t)y * w + x] ? 255u : 0u;
            p[0] = p[1] = p[2] = v;
            p[3] = 255u;
        }
    }
    free(core);

    *outW = w; *outH = h;
    *outHotX = hotX; *outHotY = hotY;
    return pixels;
}

/* Preserve the exact macOS cursor silhouette and hotspot without forwarding
 * CoreGraphics' semi-transparent premultiplied colors verbatim. Windows App's
 * classic 24-bpp pointer path is reliable when every visible pixel is fully
 * opaque, but has rendered some native alpha edges inverted, tinted, or absent.
 * Quantizing only the color/alpha (not the geometry) gives us native diagonal
 * resize corners and future cursor shapes without an ever-growing semantic
 * classifier. The classifier above remains an opt-in emergency fallback. */
static uint8_t *copySanitizedNativeCursor(const uint8_t *bgra,
                                          uint32_t w, uint32_t h) {
    if (!bgra || w == 0 || h == 0) return NULL;
    uint8_t *out = calloc((size_t)w * h, 4u);
    if (!out) return NULL;

    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++) {
            const uint8_t *src = bgra + ((size_t)y * w + x) * 4u;
            const uint8_t alpha = src[3];
            if (alpha < 64u) continue;

            /* CGS supplies premultiplied BGRA. Recover straight RGB before
             * reducing it to a stable black/white pointer color. */
            uint32_t b = src[0], g = src[1], r = src[2];
            if (alpha < 255u) {
                b = (b * 255u + alpha / 2u) / alpha;
                g = (g * 255u + alpha / 2u) / alpha;
                r = (r * 255u + alpha / 2u) / alpha;
                if (b > 255u) b = 255u;
                if (g > 255u) g = 255u;
                if (r > 255u) r = 255u;
            }
            const uint32_t luminance = 29u * b + 150u * g + 77u * r;
            const uint8_t value = luminance >= (128u * 256u) ? 255u : 0u;
            uint8_t *dst = out + ((size_t)y * w + x) * 4u;
            dst[0] = dst[1] = dst[2] = value;
            dst[3] = 255u;
        }
    }
    return out;
}

- (void)poll {
    /* Cheap pre-check: the CGS seed bumps on every cursor change. If it hasn't
     * moved since our last read, the shape is identical — skip the full read. */
    int seed = CGSCurrentCursorSeed();
    if (_haveSeed && seed == _lastSeed) return;
    _lastSeed = seed;
    _haveSeed = YES;

    uint32_t w = 0, h = 0;
    uint16_t hotX = 0, hotY = 0;
    /* Owned malloc'd BGRA buffer; freed below after the handler runs. */
    uint8_t *bgra = [self copyLiveCursorBGRA:&w height:&h hotX:&hotX hotY:&hotY];
    if (!bgra || w == 0 || h == 0) { free(bgra); return; }

    const char *cursorMode = getenv("RDP_CURSOR_MODE");
    const BOOL classifiedFallback =
        cursorMode && strcmp(cursorMode, "classified") == 0;
    if (classifiedFallback) {
        RDPCompatibilityCursorKind compatibility =
            classifyCompatibilityCursor(bgra, w, h, hotX, hotY);
        if (compatibility != RDPCompatibilityCursorNative) {
            uint8_t *compat = copyCompatibilityCursor(compatibility,
                                                       &w, &h, &hotX, &hotY);
            if (compat) {
                free(bgra);
                bgra = compat;
                rdp_verbose("using classified compatibility %s cursor",
                            compatibilityCursorName(compatibility));
            }
        }
    } else {
        uint8_t *sanitized = copySanitizedNativeCursor(bgra, w, h);
        if (sanitized) {
            free(bgra);
            bgra = sanitized;
        }
    }

    uint64_t hash = fnv1a(bgra, (size_t)w * h * 4, 0);
    hash = fnv1a((const uint8_t *)&w, sizeof(w), hash);
    hash = fnv1a((const uint8_t *)&h, sizeof(h), hash);
    hash = fnv1a((const uint8_t *)&hotX, sizeof(hotX), hash);
    hash = fnv1a((const uint8_t *)&hotY, sizeof(hotY), hash);

    if (hash == _lastHash) { free(bgra); return; }
    _lastHash = hash;

    rdp_verbose("cursor shape changed: %ux%u hot=(%u,%u) — sending", w, h, hotX, hotY);
    if (self.handler) self.handler(bgra, w, h, hotX, hotY);
    free(bgra);
}

/* Read the live on-screen system cursor via the private CGS API and return it as
 * a freshly malloc'd 32-bit BGRA premultiplied, top-left-origin, tightly-packed
 * buffer (stride == w*4), scaled down to kMaxCursorDim. Returns NULL on failure,
 * in which case the caller may try the NSCursor fallback. Caller frees. */
- (uint8_t *)copyLiveCursorBGRA:(uint32_t *)outW height:(uint32_t *)outH
                           hotX:(uint16_t *)outHotX hotY:(uint16_t *)outHotY {
    CGSConnectionID cid = CGSMainConnectionID();
    if (cid == 0) return [self copyFallbackCursorBGRA:outW height:outH
                                                 hotX:outHotX hotY:outHotY];

    size_t dataSize = 0;
    if (CGSGetGlobalCursorDataSize(cid, &dataSize) != kCGErrorSuccess ||
        dataSize == 0 || dataSize > (64u * 1024u * 1024u)) {
        return [self copyFallbackCursorBGRA:outW height:outH
                                       hotX:outHotX hotY:outHotY];
    }

    uint8_t *raw = malloc(dataSize);
    if (!raw) return NULL;

    /* CGSGetGlobalCursorData treats outDataSize as an in/out capacity. Passing
     * zero still returns metadata but leaves the pixel buffer untouched, which
     * previously made us encode uninitialized memory as an RDP cursor. */
    int    rdDataSize = (int)dataSize;
    int    rowBytes = 0, depth = 0, comps = 0, bpc = 0;
    CGRect rect = CGRectZero;
    CGPoint hot = CGPointZero;
    CGError ge = CGSGetGlobalCursorData(cid, raw, &rdDataSize, &rowBytes,
                                        &rect, &hot, &depth, &comps, &bpc);
    if (ge != kCGErrorSuccess || rdDataSize <= 0 ||
        (size_t)rdDataSize > dataSize || rowBytes <= 0 ||
        depth != 32 || bpc != 8 ||
        rect.size.width <= 0 || rect.size.height <= 0) {
        rdp_debug("CGSGetGlobalCursorData unusable (err=%d bytes=%d/%zu depth=%d "
                  "bpc=%d %gx%g) — falling back", ge, rdDataSize, dataSize,
                  depth, bpc,
                  rect.size.width, rect.size.height);
        free(raw);
        return [self copyFallbackCursorBGRA:outW height:outH
                                       hotX:outHotX hotY:outHotY];
    }

    uint32_t srcW = (uint32_t)llround(rect.size.width);
    uint32_t srcH = (uint32_t)llround(rect.size.height);
    if (srcW == 0 || srcH == 0 ||
        (size_t)rowBytes * srcH > (size_t)rdDataSize) {
        free(raw);
        return NULL;
    }

    /* CGS returns native BGRA-premultiplied rows in TOP-DOWN order. Preserve
     * them verbatim whenever no resize is needed. Wrapping these bytes as
     * big-endian ARGB and drawing through a flipped Quartz context used to swap
     * color/alpha interpretation and invert the cursor vertically. */
    uint32_t maxDim = srcW > srcH ? srcW : srcH;
    if (maxDim <= kMaxCursorDim) {
        const size_t dstStride = (size_t)srcW * 4u;
        uint8_t *out = malloc(dstStride * srcH);
        if (!out) { free(raw); return NULL; }
        for (uint32_t y = 0; y < srcH; y++)
            memcpy(out + (size_t)y * dstStride,
                   raw + (size_t)y * (size_t)rowBytes, dstStride);

        *outW = srcW;
        *outH = srcH;
        long hx = llround(hot.x);
        long hy = llround(hot.y);
        if (hx < 0) hx = 0;
        if (hy < 0) hy = 0;
        if ((uint32_t)hx >= srcW) hx = (long)srcW - 1;
        if ((uint32_t)hy >= srcH) hy = (long)srcH - 1;
        *outHotX = (uint16_t)hx;
        *outHotY = (uint16_t)hy;
        free(raw);
        return out;
    }

    /* Oversized accessibility cursors still need to be scaled to the client's
     * 96px Large Pointer limit. The raw layout is BGRA/little-endian. */
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    if (!cs) { free(raw); return NULL; }

    CGDataProviderRef provider =
        CGDataProviderCreateWithData(NULL, raw, (size_t)rowBytes * srcH, NULL);
    if (!provider) { CGColorSpaceRelease(cs); free(raw); return NULL; }

    /* PremultipliedFirst + ByteOrder32Little is BGRA in memory. */
    CGImageRef src = CGImageCreate(
        srcW, srcH, 8, 32, (size_t)rowBytes, cs,
        kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little,
        provider, NULL, false, kCGRenderingIntentDefault);
    CGDataProviderRelease(provider);
    CGColorSpaceRelease(cs);
    if (!src) { free(raw); return NULL; }

    uint8_t *out = [self renderCGImage:src
                              srcWidth:srcW srcHeight:srcH
                               hotSpot:hot
                                 width:outW height:outH
                                  hotX:outHotX hotY:outHotY];
    CGImageRelease(src);
    free(raw);   /* CGImage held its own ref via the provider's copied data */
    return out;
}

/* Render a CGImage into a freshly malloc'd 32-bit BGRA premultiplied,
 * top-left-origin, tightly-packed buffer, scaled down to kMaxCursorDim. The
 * destination context is top-left origin (flipped), so no manual row flip is
 * needed. Returns NULL on failure. Caller frees. */
- (uint8_t *)renderCGImage:(CGImageRef)src
                  srcWidth:(uint32_t)srcW srcHeight:(uint32_t)srcH
                   hotSpot:(CGPoint)hot
                     width:(uint32_t *)outW height:(uint32_t *)outH
                      hotX:(uint16_t *)outHotX hotY:(uint16_t *)outHotY {
    uint32_t w = srcW, h = srcH;
    double scale = 1.0;
    uint32_t maxDim = w > h ? w : h;
    if (maxDim > kMaxCursorDim) {
        scale = (double)kMaxCursorDim / (double)maxDim;
        w = (uint32_t)llround(srcW * scale);
        h = (uint32_t)llround(srcH * scale);
        if (w == 0) w = 1;
        if (h == 0) h = 1;
    }

    size_t stride = (size_t)w * 4;
    size_t bytes  = stride * h;
    uint8_t *buf = calloc(1, bytes);
    if (!buf) return NULL;

    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    if (!cs) { free(buf); return NULL; }

    /* kCGImageAlphaPremultipliedFirst + ByteOrder32Little == BGRA byte order
     * (B,G,R,A) in memory, premultiplied — exactly the RDP color-pointer xor
     * layout we want. */
    CGContextRef cgctx = CGBitmapContextCreate(
        buf, w, h, 8, stride, cs,
        kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
    CGColorSpaceRelease(cs);
    if (!cgctx) { free(buf); return NULL; }

    /* CGS and the destination bitmap both use the same top-down row order here;
     * do not apply another vertical flip. */
    CGContextSetInterpolationQuality(cgctx, kCGInterpolationHigh);
    CGContextDrawImage(cgctx, CGRectMake(0, 0, w, h), src);
    CGContextRelease(cgctx);

    *outW = w;
    *outH = h;
    /* Hotspot in source points -> scaled target pixels, clamped to bounds. */
    long hx = llround(hot.x * scale);
    long hy = llround(hot.y * scale);
    if (hx < 0) hx = 0; if ((uint32_t)hx >= w) hx = w ? (long)w - 1 : 0;
    if (hy < 0) hy = 0; if ((uint32_t)hy >= h) hy = h ? (long)h - 1 : 0;
    *outHotX = (uint16_t)hx;
    *outHotY = (uint16_t)hy;
    return buf;
}

/* Last-resort fallback when the CGS cursor read is unavailable. NSCursor is
 * AppKit/main-thread-affine and unreliable headless, but reading its `.image`
 * (a plain NSImage) and rasterizing via CoreGraphics does not require a run
 * loop, so it is safe to attempt from our background queue. Logged so the
 * limitation is visible in a hardware test. */
- (uint8_t *)copyFallbackCursorBGRA:(uint32_t *)outW height:(uint32_t *)outH
                               hotX:(uint16_t *)outHotX hotY:(uint16_t *)outHotY {
    NSCursor *cursor = [NSCursor currentSystemCursor];
    if (!cursor) cursor = [NSCursor currentCursor];
    NSImage *image = cursor.image;
    if (!image) return NULL;

    CGImageRef cg = [image CGImageForProposedRect:NULL context:nil hints:nil];
    if (!cg) return NULL;
    uint32_t srcW = (uint32_t)CGImageGetWidth(cg);
    uint32_t srcH = (uint32_t)CGImageGetHeight(cg);
    if (srcW == 0 || srcH == 0) return NULL;

    NSPoint hs = cursor.hotSpot;
    /* hotSpot is in image points; CGImage may be at a higher pixel scale. */
    NSSize pt = image.size;
    CGPoint hot = CGPointMake(
        pt.width  > 0 ? hs.x * (srcW / pt.width)  : hs.x,
        pt.height > 0 ? hs.y * (srcH / pt.height) : hs.y);

    rdp_debug("cursor read via NSCursor fallback (%ux%u) — CGS unavailable", srcW, srcH);
    return [self renderCGImage:cg srcWidth:srcW srcHeight:srcH hotSpot:hot
                         width:outW height:outH hotX:outHotX hotY:outHotY];
}

@end
