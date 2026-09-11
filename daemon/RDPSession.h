#pragma once
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#include "protocol/RDPUDP2.h"

NS_ASSUME_NONNULL_BEGIN

@class RDPSession;

@protocol RDPSessionDelegate <NSObject>
- (void)sessionDidEnd:(RDPSession *)session error:(nullable NSError *)error;

/* Called (on the session's own queue) once a session has authenticated its
 * client and is about to bring up its virtual display. The delegate (RDPServer)
 * makes this the single active session, superseding any currently-active one:
 * it signals the old session to disconnect and BLOCKS until the old session has
 * released its display, then returns YES so the caller may proceed. Returns NO
 * if this session should abort (e.g. it was itself superseded while waiting, or
 * the server is shutting down). */
- (BOOL)sessionDidAuthenticateAndRequestActivation:(RDPSession *)session;

/* Standard MS-RDPBCGR auto-reconnect. The new transport presents the opaque
 * 28-byte verifier previously issued to the active desktop. The server matches
 * it against suspended sessions and transfers the retained virtual display. */
- (BOOL)session:(RDPSession *)session
    requestResumeWithReconnectCookie:(NSData *)reconnectCookie;

/* FreeRDP has generated the per-connection RDPEMT request ID/cookie and is
 * about to send them over the authenticated TCP connection. */
- (BOOL)session:(RDPSession *)session
    didOfferMultitransportRequestID:(uint32_t)requestID
                     securityCookie:(NSData *)securityCookie;
- (BOOL)session:(RDPSession *)session
    sendUdpDynamicChannelData:(NSData *)data;

/* Per-client UDP circuit breaker. The decision is made before FreeRDP sends
 * its capability set; a failure notification opens the breaker for subsequent
 * reconnects from that client address. */
- (BOOL)sessionShouldOfferReliableUDP:(RDPSession *)session;
- (void)sessionReliableUDPTunnelDidFailAfterSoftSync:(RDPSession *)session;
@end

typedef NS_ENUM(NSInteger, RDPSessionState) {
    RDPSessionStateConnecting,
    RDPSessionStateNegotiating,
    RDPSessionStateActive,
    RDPSessionStateSuspended,
    RDPSessionStateDisconnecting,
    RDPSessionStateDisconnected,
};

@interface RDPSession : NSObject

@property (nonatomic, readonly) int clientFd;
@property (nonatomic, readonly) RDPSessionState state;
@property (nonatomic, readonly) NSString *clientAddress;
@property (nonatomic, weak, nullable) id<RDPSessionDelegate> delegate;

- (instancetype)initWithFileDescriptor:(int)fd clientAddress:(NSString *)address;
- (void)start;

/* Request that this session disconnect. Sets the state to Disconnecting so the
 * peer run loop exits and teardown runs (releasing the virtual display + display
 * assertions). Safe to call from any thread; returns immediately. */
- (void)disconnect;

/* Superseding clients must release the shared BetterDisplay promptly. This
 * variant shuts down the old transport to interrupt a blocked writer and skips
 * the best-effort graceful-close PDU during teardown. */
- (void)disconnectForReplacement;

/* Block the calling thread until this session's teardown has fully completed
 * (virtual display released, peer destroyed). Returns YES if teardown finished
 * within `timeout` seconds, NO on timeout. Used by the takeover path so a new
 * session does not create its virtual display until the superseded one has
 * released the display. MUST NOT be called from the session's own queue (that
 * would deadlock) — call it from the superseding session's queue. */
- (BOOL)waitForTeardown:(NSTimeInterval)timeout;

/* Server-side reconnect helpers. Cookie comparison is constant-time and the
 * transfer moves only the BetterDisplay/display assertion objects; every
 * transport-bound channel and capture pipeline is recreated by the receiver. */
- (BOOL)matchesReconnectCookie:(NSData *)reconnectCookie;
- (BOOL)adoptRetainedDesktopFromSession:(RDPSession *)session;

/* Called by the authenticated same-port RDPEMT listener. Safe from its UDP
 * queue; the peer wrapper serializes access to FreeRDP's VCM. */
- (void)udpTunnelDidBecomeReady;
- (void)udpTunnelDidFail;
- (BOOL)receiveUdpDynamicChannelData:(NSData *)data;
- (void)updateUDPTransportStats:(const RDPUDP2Stats *)stats
                   observedAtMS:(uint64_t)observedAtMS
                    queuedBytes:(uint32_t)queuedBytes;

@end

NS_ASSUME_NONNULL_END
