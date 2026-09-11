#pragma once
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <IOSurface/IOSurface.h>

NS_ASSUME_NONNULL_BEGIN

/* ScreenCaptureKit can report many disjoint damage rectangles for one frame.
 * Preserve them through the capture pipeline instead of expanding them to one
 * bounding box: Progressive operates on 64x64 tiles, so the empty space between
 * unrelated rectangles otherwise becomes needless CPU work and network data.
 * The fixed bound keeps coalescing allocation-free on SCStream's callback queue. */
#define SCREEN_CAPTURE_MAX_DIRTY_RECTS 64

typedef struct {
    uint32_t count;
    CGRect rects[SCREEN_CAPTURE_MAX_DIRTY_RECTS];
    BOOL collapsedToBounds;
} ScreenCaptureDirtyRegion;

typedef void (^ScreenCaptureFrameBlock)(IOSurfaceRef surface,
                                        uint32_t width, uint32_t height,
                                        const ScreenCaptureDirtyRegion *dirtyRegion);

@interface ScreenCapture : NSObject

@property (nonatomic, readonly) BOOL isCapturing;
@property (nonatomic, copy, nullable) ScreenCaptureFrameBlock frameHandler;

- (instancetype)initWithDisplayID:(CGDirectDisplayID)displayID;
- (BOOL)startWithWidth:(uint32_t)width height:(uint32_t)height;
/* Immediately return an adaptively-idled stream to its full capture rate.
 * Safe to call from the RDP peer thread; the implementation serializes the
 * ScreenCaptureKit reconfiguration onto its private capture queue. */
- (void)noteRemoteInputActivity;
/* Keep the active rate for meaningful pixel motion already confirmed by the
 * Progressive tile filter (video/animation without a corresponding input). */
- (void)noteVisualActivity;
/* Update the live ScreenCaptureKit ceiling after transport negotiation. This
 * lets a clean LAN RDP-UDP path use 60 fps while WAN/TCP sessions keep their
 * conservative resolution-aware rate. */
- (void)setPreferredFrameRate:(uint32_t)framesPerSecond;
- (void)stop;

@end

NS_ASSUME_NONNULL_END
