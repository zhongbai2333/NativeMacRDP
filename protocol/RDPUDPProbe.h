#pragma once

#import <Foundation/Foundation.h>
#include "protocol/RDPUDP2.h"

NS_ASSUME_NONNULL_BEGIN

/*
 * Isolated server-side MS-RDPEUDP handshake probe.
 *
 * FreeRDP 3.30 advertises and sends the MS-RDPEMT bootstrap request, but its
 * server does not create the same-port UDP listener.  This object owns that
 * listener while RDP_UDP_PROBE=1, answers the versioned RDP-UDP SYN, and logs
 * the first RDPUDP2 packets.  It deliberately does not claim that the UDP
 * tunnel is usable yet: TLS and the MS-RDPEMT tunnel data plane are the next
 * layer and remain on the isolated test endpoint until implemented.
 */
@interface RDPUDPProbe : NSObject

/* Called on the probe's serial queue with a point-in-time copy. The receiver
 * must copy any fields it needs before returning. */
@property (nonatomic, copy, nullable) void (^metricsHandler)(
    id session, const RDPUDP2Stats *stats, uint64_t observedAtMS,
    uint32_t queuedBytes);

- (instancetype)initWithPort:(uint16_t)port bindAddress:(NSString *)bindAddress;
- (BOOL)startWithError:(NSError **)error;
- (void)stop;

/* Register credentials generated on the authenticated TCP peer before its
 * Initiate Multitransport Request is sent. The UDP SYN carries SHA-256(cookie),
 * and RDPEMT later carries the exact cookie. */
- (void)registerRequestID:(uint32_t)requestID
           securityCookie:(NSData *)securityCookie
                forSession:(id)session;
- (void)unregisterSession:(id)session;

/* Enqueue one raw DRDYNVC PDU for RDPEMT/TLS/RDPUDP2 delivery. */
- (BOOL)sendDynamicChannelData:(NSData *)data forSession:(id)session;

@end

NS_ASSUME_NONNULL_END
