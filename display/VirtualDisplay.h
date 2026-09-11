#pragma once
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

/*
 * VirtualDisplay: manages which CGDirectDisplayID the session captures.
 *
 * The supported deployment asks an external BetterDisplay helper to create and
 * resize the session display. If no helper is configured, the optional
 * MACOS_RDP_VIRTUAL_DISPLAY fallback resolves undocumented CGVirtualDisplay
 * classes at runtime and otherwise falls back to CGMainDisplayID().
 */
@interface VirtualDisplay : NSObject

@property (nonatomic, readonly) CGDirectDisplayID displayID;
@property (nonatomic, readonly) uint32_t width;
@property (nonatomic, readonly) uint32_t height;

- (instancetype)initWithWidth:(uint32_t)width height:(uint32_t)height;
- (BOOL)create;
- (void)destroy;
- (void)setResolutionWidth:(uint32_t)width height:(uint32_t)height;
/* Resize the already-connected display without restoring/disconnecting it.
 * The BetterDisplay helper reuses the same named virtual screen, preserving
 * the WindowServer desktop and all application/window state. */
- (BOOL)resizeToWidth:(uint32_t)width height:(uint32_t)height;

@end

NS_ASSUME_NONNULL_END
