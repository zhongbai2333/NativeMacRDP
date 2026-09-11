#import "daemon/RDPServer.h"
#import "daemon/RDPSession.h"
#import "protocol/RDPUDPProbe.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <netdb.h>
#import <arpa/inet.h>
#import <fcntl.h>
#import <unistd.h>
#include <math.h>
#define RDP_LOG_COMPONENT "server"
#include "logging/RDPLog.h"
#include <stdatomic.h>

@interface RDPServer () <RDPSessionDelegate>
@property (nonatomic, assign) int listenFd;
@property (nonatomic, assign) uint16_t portValue;
@property (nonatomic, copy) NSString *bindAddressValue;
@property (nonatomic, assign) BOOL running;
@property (nonatomic, strong) NSMutableArray<RDPSession *> *sessions;
@property (nonatomic, strong) dispatch_source_t acceptSource;
@property (nonatomic, strong) dispatch_queue_t acceptQueue;
@property (nonatomic, strong, nullable) RDPUDPProbe *udpProbe;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDate *> *udpBlockedUntil;
/* The single active (authenticated) session that owns the display. Guarded by
 * @synchronized(self) along with `sessions`. A new client that authenticates
 * supersedes whatever is here. */
@property (nonatomic, strong, nullable) RDPSession *activeSession;
@end

/* Process-wide active-session flag. The daemon runs a single RDPServer, so a
 * class-level flag faithfully mirrors that instance's `_activeSession`. The
 * auto-updater reads this (off any thread) to decide whether to defer a swap. */
/* Previously volatile int32_t: volatile prevents register caching but not
 * CPU reordering — readers on other cores could see stale values.
 * _Atomic with acquire/release gives the correct happens-before guarantee. */
static _Atomic int32_t g_hasActiveSession = 0;

@implementation RDPServer

+ (BOOL)hasActiveSession {
    return atomic_load_explicit(&g_hasActiveSession, memory_order_acquire) != 0;
}

- (void)updateActiveSessionFlag {
    /* Caller holds @synchronized(self); the store pairs with the acquire load
     * in +hasActiveSession to form a proper happens-before edge. */
    atomic_store_explicit(&g_hasActiveSession,
                          (_activeSession != nil) ? 1 : 0,
                          memory_order_release);
}

- (instancetype)initWithPort:(uint16_t)port bindAddress:(NSString *)bindAddress {
    if ((self = [super init])) {
        _portValue = port;
        _bindAddressValue = [bindAddress copy];
        _listenFd  = -1;
        _sessions  = [NSMutableArray array];
        _udpBlockedUntil = [NSMutableDictionary dictionary];
        _acceptQueue = dispatch_queue_create("com.macosrdp.accept",
                                             DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (uint16_t)port    { return _portValue; }
- (NSString *)bindAddress { return _bindAddressValue; }
- (BOOL)isRunning   { return _running; }

- (BOOL)startWithError:(NSError **)error {
    rdp_verbose("resolving listen address %s:%u",
                _bindAddressValue.UTF8String, _portValue);

    char portText[16];
    snprintf(portText, sizeof(portText), "%u", _portValue);
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;
    struct addrinfo *resolved = NULL;
    int gai = getaddrinfo(_bindAddressValue.UTF8String, portText, &hints, &resolved);
    if (gai != 0 || !resolved) {
        rdp_error("getaddrinfo(%s) failed: %s",
                  _bindAddressValue.UTF8String, gai_strerror(gai));
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                code:EINVAL userInfo:nil];
        return NO;
    }

    int fd = -1;
    int savedErrno = EADDRNOTAVAIL;
    for (struct addrinfo *ai = resolved; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) { savedErrno = errno; continue; }

        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;

        savedErrno = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(resolved);

    if (fd < 0) {
        rdp_error("bind() failed on %s:%u: %s",
                  _bindAddressValue.UTF8String, _portValue, strerror(savedErrno));
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                code:savedErrno userInfo:nil];
        return NO;
    }
    if (listen(fd, 8) < 0) {
        rdp_error("listen() failed: %s", strerror(errno));
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                code:errno userInfo:nil];
        close(fd);
        return NO;
    }

    _listenFd = fd;
    _running  = YES;
    rdp_debug("listen socket fd=%d ready on %s:%u", fd,
              _bindAddressValue.UTF8String, _portValue);

    _acceptSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                           (uintptr_t)fd, 0, _acceptQueue);
    __weak typeof(self) weak = self;
    dispatch_source_set_event_handler(_acceptSource, ^{
        [weak acceptConnection];
    });
    dispatch_resume(_acceptSource);

    const char *udpProbe = getenv("RDP_UDP_PROBE");
    if (udpProbe && strcmp(udpProbe, "1") == 0) {
        _udpProbe = [[RDPUDPProbe alloc] initWithPort:_portValue
                                         bindAddress:_bindAddressValue];
        _udpProbe.metricsHandler = ^(id session,
                                     const RDPUDP2Stats *stats,
                                     uint64_t observedAtMS,
                                     uint32_t queuedBytes) {
            if ([session isKindOfClass:[RDPSession class]])
                [(RDPSession *)session updateUDPTransportStats:stats
                                                  observedAtMS:observedAtMS
                                                   queuedBytes:queuedBytes];
        };
        NSError *udpError = nil;
        if (![_udpProbe startWithError:&udpError]) {
            rdp_error("isolated UDP probe requested but could not start: %s",
                      udpError.localizedDescription.UTF8String);
            [_udpProbe stop];
            _udpProbe = nil;
            dispatch_source_cancel(_acceptSource);
            _acceptSource = nil;
            close(_listenFd);
            _listenFd = -1;
            _running = NO;
            if (error) *error = udpError;
            return NO;
        }
    }
    return YES;
}

- (void)acceptConnection {
    struct sockaddr_storage clientAddr = {0};
    socklen_t len = sizeof(clientAddr);
    int clientFd = accept(_listenFd, (struct sockaddr *)&clientAddr, &len);
    if (clientFd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            rdp_error("accept() failed: %s", strerror(errno));
        return;
    }

    char addrBuf[NI_MAXHOST] = {0};
    int nameRc = getnameinfo((struct sockaddr *)&clientAddr, len,
                             addrBuf, sizeof(addrBuf), NULL, 0,
                             NI_NUMERICHOST);
    if (nameRc != 0) snprintf(addrBuf, sizeof(addrBuf), "unknown");
    NSString *addr = [NSString stringWithUTF8String:addrBuf];

    rdp_verbose("accepted connection from %s (fd=%d)", addrBuf, clientFd);

    RDPSession *session = [[RDPSession alloc] initWithFileDescriptor:clientFd
                                                       clientAddress:addr];
    session.delegate = self;

    @synchronized(self) { [_sessions addObject:session]; }
    rdp_debug("active sessions: %lu", (unsigned long)_sessions.count);

    [self.delegate serverDidAcceptSession:session];
    [session start];
}

- (void)stop {
    rdp_info("stopping server");
    _running = NO;
    [_udpProbe stop];
    _udpProbe = nil;
    if (_acceptSource) {
        dispatch_source_cancel(_acceptSource);
        _acceptSource = nil;
    }
    if (_listenFd >= 0) {
        close(_listenFd);
        _listenFd = -1;
    }
    NSArray<RDPSession *> *sessions = nil;
    @synchronized(self) {
        sessions = [_sessions copy];
        rdp_verbose("disconnecting %lu active sessions",
                    (unsigned long)sessions.count);
        _activeSession = nil;
        [self updateActiveSessionFlag];
    }

    /* Do not let main return (and launchd kill the process image) while session
     * queues are still preparing the standard RDP disconnect sequence. Waiting
     * outside the server lock lets sessionDidEnd remove completed sessions. */
    for (RDPSession *session in sessions)
        [session disconnect];

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:4.0];
    for (RDPSession *session in sessions) {
        NSTimeInterval remaining = [deadline timeIntervalSinceNow];
        if (remaining <= 0.0 || ![session waitForTeardown:remaining]) {
            rdp_error("shutdown deadline reached while closing session %s",
                      session.clientAddress.UTF8String);
            break;
        }
    }

    @synchronized(self) {
        [_sessions removeObjectsInArray:sessions];
    }
}

- (BOOL)session:(RDPSession *)session
    requestResumeWithReconnectCookie:(NSData *)reconnectCookie {
    if (!_running || reconnectCookie.length == 0) return NO;

    RDPSession *retained = nil;
    BOOL adopted = NO;
    @synchronized(self) {
        for (RDPSession *candidate in _sessions) {
            if (candidate != session &&
                [candidate matchesReconnectCookie:reconnectCookie]) {
                retained = candidate;
                break;
            }
        }
        /* Match, transfer, and ownership swap are one server-side transaction.
         * Otherwise a newly authenticated session could claim the display in
         * the gap after adoption and make the reconnecting session tear down a
         * desktop it no longer owns. */
        if (retained && _activeSession == retained &&
            [session adoptRetainedDesktopFromSession:retained]) {
            _activeSession = session;
            [self updateActiveSessionFlag];
            adopted = YES;
        }
    }
    if (!adopted) {
        rdp_info("auto-reconnect proof did not match the active retained desktop");
        return NO;
    }
    rdp_info("FAST RECONNECT: %s resumed retained desktop from %s",
             session.clientAddress.UTF8String,
             retained.clientAddress.UTF8String);
    return YES;
}

/* A session authenticated its client and wants to own the display. Make it the
 * single active session, superseding (disconnecting + waiting on the teardown
 * of) any session currently active. Called on the NEW session's serial queue;
 * the blocking wait happens off-lock so concurrent connection attempts don't
 * stall. Returns NO if the server is stopping. */
- (BOOL)sessionDidAuthenticateAndRequestActivation:(RDPSession *)session {
    if (!_running) {
        rdp_info("activation refused: server is stopping");
        return NO;
    }

    RDPSession *previous = nil;
    @synchronized(self) {
        previous = _activeSession;
        if (previous == session) {
            rdp_verbose("session %s already active", session.clientAddress.UTF8String);
            return YES;
        }
        /* Claim active immediately so a third concurrent client that authenticates
         * supersedes US in turn rather than racing on a stale pointer. */
        _activeSession = session;
        [self updateActiveSessionFlag];
    }

    if (previous) {
        rdp_info("TAKEOVER: %s superseding active session %s",
                 session.clientAddress.UTF8String,
                 previous.clientAddress.UTF8String);
        /* Tell the old session to exit its peer loop + tear down (releases its
         * virtual display + display assertions), then block until it has done so
         * BEFORE we let the new session create its own virtual display — two live
         * virtual displays would both map to the main display and fight. */
        [previous disconnectForReplacement];
        if (![previous waitForTeardown:10.0]) {
            rdp_error("TAKEOVER: previous session %s did not tear down in time — "
                      "refusing replacement to protect the shared display",
                      previous.clientAddress.UTF8String);
            @synchronized(self) {
                if (_activeSession == session) _activeSession = nil;
                [self updateActiveSessionFlag];
            }
            return NO;
        } else {
            rdp_info("TAKEOVER: previous session %s released the display",
                     previous.clientAddress.UTF8String);
        }
    } else {
        rdp_info("session %s is now the active session (no prior session)",
                 session.clientAddress.UTF8String);
    }

    /* If a still-newer client superseded us while we waited, abort. */
    @synchronized(self) {
        if (_activeSession != session) {
            rdp_info("session %s was superseded while activating — aborting",
                     session.clientAddress.UTF8String);
            [self updateActiveSessionFlag];
            return NO;
        }
    }
    return YES;
}

- (void)sessionDidEnd:(RDPSession *)session error:(NSError *)error {
    [_udpProbe unregisterSession:session];
    @synchronized(self) {
        [_sessions removeObject:session];
        if (_activeSession == session) _activeSession = nil;
        [self updateActiveSessionFlag];
    }
    rdp_debug("session removed; %lu remaining", (unsigned long)_sessions.count);
    [self.delegate serverSession:session didEndWithError:error];
}

- (BOOL)session:(RDPSession *)session
    didOfferMultitransportRequestID:(uint32_t)requestID
                     securityCookie:(NSData *)securityCookie {
    if (!_udpProbe || securityCookie.length != 16) return NO;
    [_udpProbe registerRequestID:requestID
                 securityCookie:securityCookie
                      forSession:session];
    return YES;
}

- (BOOL)session:(RDPSession *)session
    sendUdpDynamicChannelData:(NSData *)data {
    if (!_udpProbe || !data.length) return NO;
    return [_udpProbe sendDynamicChannelData:data forSession:session];
}

- (BOOL)sessionShouldOfferReliableUDP:(RDPSession *)session {
    if (!session.clientAddress.length) return YES;
    @synchronized(self) {
        NSDate *until = _udpBlockedUntil[session.clientAddress];
        if (!until) return YES;
        NSTimeInterval remaining = [until timeIntervalSinceNow];
        if (remaining <= 0.0) {
            [_udpBlockedUntil removeObjectForKey:session.clientAddress];
            return YES;
        }
        rdp_info("UDP circuit breaker active for %s (%.0fs remaining); "
                 "advertising TCP-only reconnect",
                 session.clientAddress.UTF8String, ceil(remaining));
        return NO;
    }
}

- (void)sessionReliableUDPTunnelDidFailAfterSoftSync:(RDPSession *)session {
    if (!session.clientAddress.length) return;
    static const NSTimeInterval kUDPCircuitBreakerSeconds = 120.0;
    @synchronized(self) {
        _udpBlockedUntil[session.clientAddress] =
            [NSDate dateWithTimeIntervalSinceNow:kUDPCircuitBreakerSeconds];
    }
    rdp_info("UDP circuit breaker opened for %s after Soft-Sync failure "
             "(next reconnect will use TCP)",
             session.clientAddress.UTF8String);
}

@end
