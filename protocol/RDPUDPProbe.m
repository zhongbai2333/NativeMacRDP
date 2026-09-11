#import "protocol/RDPUDPProbe.h"
#import "protocol/RDPUDP2.h"
#import "protocol/RDPUDPBootstrap.h"
#import "protocol/RDPEMT.h"
#import "daemon/RDPSession.h"

#import <arpa/inet.h>
#import <CommonCrypto/CommonDigest.h>
#include <errno.h>
#import <fcntl.h>
#import <netdb.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>
#import <openssl/err.h>
#import <openssl/ssl.h>

#define RDP_LOG_COMPONENT "udp"
#include "logging/RDPLog.h"

static uint16_t read_be16(const uint8_t *p) {
    uint16_t v = 0;
    memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

static uint32_t read_be32(const uint8_t *p) {
    uint32_t v = 0;
    memcpy(&v, p, sizeof(v));
    return ntohl(v);
}

static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static BOOL env_enabled(const char *name) {
    const char *value = getenv(name);
    return value && (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 ||
                     strcasecmp(value, "yes") == 0);
}

static void peer_text(const struct sockaddr *address, socklen_t addressLength,
                      char host[NI_MAXHOST], char service[NI_MAXSERV]) {
    int rc = getnameinfo(address, addressLength,
                         host, NI_MAXHOST, service, NI_MAXSERV,
                         NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        snprintf(host, NI_MAXHOST, "unknown");
        snprintf(service, NI_MAXSERV, "?");
    }
}

static BOOL peer_matches(const struct sockaddr_storage *expected,
                         socklen_t expectedLength,
                         const struct sockaddr *candidate,
                         socklen_t candidateLength) {
    if (!expected || !candidate || expectedLength < sizeof(sa_family_t) ||
        candidateLength < sizeof(sa_family_t) ||
        expected->ss_family != candidate->sa_family)
        return NO;
    if (candidate->sa_family == AF_INET) {
        if (expectedLength < sizeof(struct sockaddr_in) ||
            candidateLength < sizeof(struct sockaddr_in))
            return NO;
        const struct sockaddr_in *lhs = (const struct sockaddr_in *)expected;
        const struct sockaddr_in *rhs = (const struct sockaddr_in *)candidate;
        return lhs->sin_port == rhs->sin_port &&
               lhs->sin_addr.s_addr == rhs->sin_addr.s_addr;
    }
    if (candidate->sa_family == AF_INET6) {
        if (expectedLength < sizeof(struct sockaddr_in6) ||
            candidateLength < sizeof(struct sockaddr_in6))
            return NO;
        const struct sockaddr_in6 *lhs = (const struct sockaddr_in6 *)expected;
        const struct sockaddr_in6 *rhs = (const struct sockaddr_in6 *)candidate;
        return lhs->sin6_port == rhs->sin6_port &&
               lhs->sin6_scope_id == rhs->sin6_scope_id &&
               memcmp(&lhs->sin6_addr, &rhs->sin6_addr,
                      sizeof(lhs->sin6_addr)) == 0;
    }
    return expectedLength == candidateLength &&
           memcmp(expected, candidate, expectedLength) == 0;
}

static uint64_t monotonic_milliseconds(void) {
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000u;
}

@interface RDPUDPBootstrapRecord : NSObject
@property (nonatomic, assign) uint32_t requestID;
@property (nonatomic, copy) NSData *cookie;
@property (nonatomic, weak) id session;
@end

@implementation RDPUDPBootstrapRecord
@end

@interface RDPUDPProbe () {
    int _udpFd;
    uint16_t _port;
    NSString *_bindAddress;
    dispatch_queue_t _queue;
    dispatch_source_t _readSource;
    dispatch_source_t _timerSource;

    struct sockaddr_storage _activePeer;
    socklen_t _activePeerLength;
    BOOL _haveActivePeer;
    BOOL _awaitingFinalAck;
    BOOL _usingRdpUdp2;
    uint32_t _serverInitialSequence;
    uint16_t _negotiatedMtu;
    uint16_t _negotiatedSendMtu;
    uint16_t _negotiatedReceiveMtu;
    uint16_t _negotiatedVersion;
    uint32_t _clientInitialSequence;
    uint64_t _receivedPackets;
    NSMutableDictionary<NSData *, RDPUDPBootstrapRecord *> *_bootstrapsByHash;
    RDPUDPBootstrapRecord *_activeBootstrap;
    RDPUDP2Transport *_udp2;
    SSL_CTX *_tlsContext;
    SSL *_tls;
    RDPEMTDecoder *_emtDecoder;
    NSMutableData *_pendingTLSCiphertext;
    BOOL _tlsReady;
    BOOL _tunnelCreated;
    NSMutableData *_pendingDVCPlaintext;
    BOOL _dvcDrainScheduled;
    __weak id _pendingDVCSession;
    BOOL _transportFailed;
    uint64_t _transportGeneration;
    uint64_t _lastStatsLogMS;
    NSData *_pendingSynAck;
    uint64_t _synAckSentAtMS;
    uint8_t _synAckRetransmits;
}
- (BOOL)sendUDP2Datagram:(const uint8_t *)data length:(size_t)length;
- (void)receiveTLSCiphertext:(const uint8_t *)data length:(size_t)length;
- (BOOL)handleRDPEMTFrame:(const RDPEMTFrame *)frame;
- (void)scheduleSecureTransportFailure;
- (void)drainPendingDynamicChannelData;
- (void)scheduleDynamicChannelDrainIfNeeded;
@end

static bool udp2_send_datagram(void *context, const uint8_t *data, size_t length) {
    RDPUDPProbe *probe = (__bridge RDPUDPProbe *)context;
    return [probe sendUDP2Datagram:data length:length];
}

static void udp2_deliver_stream(void *context, const uint8_t *data, size_t length) {
    RDPUDPProbe *probe = (__bridge RDPUDPProbe *)context;
    [probe receiveTLSCiphertext:data length:length];
}

static bool rdpemt_frame_received(void *context, const RDPEMTFrame *frame) {
    RDPUDPProbe *probe = (__bridge RDPUDPProbe *)context;
    return [probe handleRDPEMTFrame:frame] ? true : false;
}

@implementation RDPUDPProbe

- (instancetype)initWithPort:(uint16_t)port bindAddress:(NSString *)bindAddress {
    if ((self = [super init])) {
        _udpFd = -1;
        _port = port;
        _bindAddress = [bindAddress copy];
        _queue = dispatch_queue_create("com.macosrdp.udp-probe", DISPATCH_QUEUE_SERIAL);
        _bootstrapsByHash = [NSMutableDictionary dictionary];
        _pendingDVCPlaintext = [NSMutableData data];
    }
    return self;
}

- (BOOL)startWithError:(NSError **)error {
    if (_udpFd >= 0) return YES;

    char portText[16];
    snprintf(portText, sizeof(portText), "%u", _port);
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV;

    struct addrinfo *resolved = NULL;
    int gai = getaddrinfo(_bindAddress.UTF8String, portText, &hints, &resolved);
    if (gai != 0 || !resolved) {
        rdp_error("UDP probe getaddrinfo(%s:%u) failed: %s",
                  _bindAddress.UTF8String, _port, gai_strerror(gai));
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
        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
            savedErrno = errno;
            close(fd);
            fd = -1;
            continue;
        }
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;

        savedErrno = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(resolved);

    if (fd < 0) {
        rdp_error("UDP probe bind failed on %s:%u: %s",
                  _bindAddress.UTF8String, _port, strerror(savedErrno));
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                code:savedErrno userInfo:nil];
        return NO;
    }

    _udpFd = fd;
    _readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                         (uintptr_t)fd, 0, _queue);
    if (!_readSource) {
        close(fd);
        _udpFd = -1;
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                                code:ENOMEM userInfo:nil];
        return NO;
    }

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(_readSource, ^{
        [weakSelf receiveAvailableDatagrams];
    });
    dispatch_source_set_cancel_handler(_readSource, ^{
        close(fd);
    });
    dispatch_resume(_readSource);

    _timerSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    dispatch_source_set_timer(_timerSource,
                              dispatch_time(DISPATCH_TIME_NOW, 25 * NSEC_PER_MSEC),
                              25 * NSEC_PER_MSEC, 5 * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(_timerSource, ^{
        typeof(self) strongSelf = weakSelf;
        if (strongSelf) [strongSelf serviceTransportTimers];
    });
    dispatch_resume(_timerSource);

    rdp_info("UDP %s listening on %s:%u (same port as TCP)",
             env_enabled("RDP_UDP_FULL_STACK") ? "transport" : "negotiation probe",
             _bindAddress.UTF8String, _port);
    return YES;
}

- (void)stop {
    dispatch_source_t source = _readSource;
    dispatch_source_t timer = _timerSource;
    _readSource = nil;
    _timerSource = nil;
    _udpFd = -1;
    if (source) dispatch_source_cancel(source);
    if (timer) dispatch_source_cancel(timer);
    [self resetSecureTransport];
    _haveActivePeer = NO;
    _awaitingFinalAck = NO;
    _usingRdpUdp2 = NO;
    _pendingSynAck = nil;
    [_bootstrapsByHash removeAllObjects];
    _activeBootstrap = nil;
}

- (void)resetSecureTransport {
    @synchronized(self) {
        [_pendingDVCPlaintext setLength:0];
        _dvcDrainScheduled = NO;
        _pendingDVCSession = nil;
        _transportFailed = NO;
        _tunnelCreated = NO;
        _transportGeneration++;
    }
    if (_emtDecoder) {
        rdpemt_decoder_free(_emtDecoder);
        _emtDecoder = NULL;
    }
    if (_tls) {
        SSL_free(_tls);
        _tls = NULL;
    }
    if (_tlsContext) {
        SSL_CTX_free(_tlsContext);
        _tlsContext = NULL;
    }
    if (_udp2) {
        rdpudp2_transport_free(_udp2);
        _udp2 = NULL;
    }
    _pendingTLSCiphertext = nil;
    _tlsReady = NO;
    _lastStatsLogMS = 0;
}

- (void)scheduleSecureTransportFailure {
    uint64_t failedGeneration = 0;
    @synchronized(self) {
        if (_transportFailed) return;
        _transportFailed = YES;
        failedGeneration = _transportGeneration;
    }
    __weak typeof(self) weakSelf = self;
    dispatch_async(_queue, ^{
        typeof(self) strongSelf = weakSelf;
        if (!strongSelf || !strongSelf->_transportFailed ||
            strongSelf->_transportGeneration != failedGeneration)
            return;

        id session = strongSelf->_activeBootstrap.session;
        [strongSelf resetSecureTransport];
        strongSelf->_usingRdpUdp2 = NO;
        strongSelf->_awaitingFinalAck = NO;
        strongSelf->_pendingSynAck = nil;
        strongSelf->_synAckRetransmits = 0;
        strongSelf->_haveActivePeer = NO;
        strongSelf->_activeBootstrap = nil;
        if ([session respondsToSelector:@selector(udpTunnelDidFail)])
            [session udpTunnelDidFail];
    });
}

- (BOOL)startSecureTransportWithSendMTU:(uint16_t)sendMTU
                             receiveMTU:(uint16_t)receiveMTU {
    [self resetSecureTransport];
    if (!_activeBootstrap || !_activeBootstrap.session) {
        rdp_error("cannot start UDP secure transport without a live TCP bootstrap");
        return NO;
    }

    _udp2 = rdpudp2_transport_new(sendMTU, receiveMTU,
                                  udp2_send_datagram, udp2_deliver_stream,
                                  (__bridge void *)self);
    _emtDecoder = rdpemt_decoder_new(rdpemt_frame_received,
                                     (__bridge void *)self);
    _tlsContext = SSL_CTX_new(TLS_server_method());
    if (!_udp2 || !_emtDecoder || !_tlsContext) {
        rdp_error("failed to allocate UDP2/TLS/RDPEMT state");
        [self resetSecureTransport];
        return NO;
    }
    SSL_CTX_set_min_proto_version(_tlsContext, TLS1_2_VERSION);
    SSL_CTX_set_security_level(_tlsContext, 1);

    const char *certDir = getenv("RDP_CERT_DIR");
    if (!certDir || !*certDir) certDir = "/etc/macos-rdp";
    char certPath[1024], keyPath[1024];
    snprintf(certPath, sizeof(certPath), "%s/server.crt", certDir);
    snprintf(keyPath, sizeof(keyPath), "%s/server.key", certDir);
    if (SSL_CTX_use_certificate_file(_tlsContext, certPath, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(_tlsContext, keyPath, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(_tlsContext) != 1) {
        unsigned long sslError = ERR_get_error();
        rdp_error("UDP TLS certificate setup failed: %s",
                  sslError ? ERR_error_string(sslError, NULL) : "unknown error");
        [self resetSecureTransport];
        return NO;
    }

    _tls = SSL_new(_tlsContext);
    BIO *incoming = BIO_new(BIO_s_mem());
    BIO *outgoing = BIO_new(BIO_s_mem());
    if (!_tls || !incoming || !outgoing) {
        if (incoming) BIO_free(incoming);
        if (outgoing) BIO_free(outgoing);
        rdp_error("failed to allocate UDP TLS memory BIOs");
        [self resetSecureTransport];
        return NO;
    }
    BIO_set_mem_eof_return(incoming, -1);
    BIO_set_mem_eof_return(outgoing, -1);
    SSL_set_bio(_tls, incoming, outgoing); /* SSL owns both BIOs. */
    SSL_set_accept_state(_tls);
    _pendingTLSCiphertext = [NSMutableData data];
    rdp_info("secure RDPUDP2 transport ready for TLS handshake "
             "(send MTU %u receive MTU %u local ISN %u peer ISN %u)",
             sendMTU, receiveMTU, _serverInitialSequence,
             _clientInitialSequence);
    return YES;
}

- (BOOL)sendUDP2Datagram:(const uint8_t *)data length:(size_t)length {
    if (_udpFd < 0 || !_haveActivePeer || !data || !length) return NO;
    ssize_t sent = sendto(_udpFd, data, length, 0,
                          (const struct sockaddr *)&_activePeer,
                          _activePeerLength);
    if (sent != (ssize_t)length) {
        rdp_error("RDPUDP2 send failed: %s", strerror(errno));
        return NO;
    }
    return YES;
}

- (void)collectTLSCiphertext {
    if (!_tls || !_pendingTLSCiphertext) return;
    BIO *outgoing = SSL_get_wbio(_tls);
    uint8_t buffer[4096];
    for (;;) {
        int count = BIO_read(outgoing, buffer, sizeof(buffer));
        if (count <= 0) break;
        [_pendingTLSCiphertext appendBytes:buffer length:(NSUInteger)count];
    }
}

- (BOOL)flushTLSCiphertext {
    [self collectTLSCiphertext];
    if (!_udp2 || !_pendingTLSCiphertext.length) return YES;
    size_t accepted = rdpudp2_transport_send(
        _udp2, _pendingTLSCiphertext.bytes, _pendingTLSCiphertext.length,
        monotonic_milliseconds());
    if (accepted) {
        [_pendingTLSCiphertext replaceBytesInRange:NSMakeRange(0, accepted)
                                         withBytes:NULL length:0];
    }
    /* A zero acceptance normally means the 4096-packet reliable send window is
     * full, not that bytes were lost. Keep the ciphertext queued; ACK handling
     * and the 25 ms timer will resume transmission as space opens. */
    return YES;
}

- (void)pumpTLS {
    if (!_tls || _transportFailed) return;
    if (!_tlsReady) {
        int rc = SSL_do_handshake(_tls);
        if (rc == 1) {
            _tlsReady = YES;
            rdp_info("RDPUDP2 TLS handshake complete: %s / %s",
                     SSL_get_version(_tls), SSL_get_cipher_name(_tls));
        } else {
            int error = SSL_get_error(_tls, rc);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                unsigned long sslError = ERR_get_error();
                rdp_error("RDPUDP2 TLS handshake failed: %s",
                          sslError ? ERR_error_string(sslError, NULL)
                                   : "protocol error");
                [self scheduleSecureTransportFailure];
                return;
            }
        }
        [self flushTLSCiphertext];
        if (!_tlsReady) return;
    }

    uint8_t plaintext[8192];
    for (;;) {
        int count = SSL_read(_tls, plaintext, sizeof(plaintext));
        if (count > 0) {
            if (!rdpemt_decoder_feed(_emtDecoder, plaintext, (size_t)count)) {
                rdp_error("invalid RDPEMT stream received over UDP TLS");
                [self scheduleSecureTransportFailure];
                return;
            }
            continue;
        }
        int error = SSL_get_error(_tls, count);
        if (error == SSL_ERROR_ZERO_RETURN) {
            rdp_error("RDPUDP2 TLS peer closed the secure tunnel");
            [self scheduleSecureTransportFailure];
        } else if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            const int savedErrno = errno;
            const unsigned long queuedError = ERR_peek_error();
            rdp_error("RDPUDP2 TLS read failed (SSL error %d, errno=%d/%s, "
                      "openssl=%s, shutdown=0x%x)",
                      error, savedErrno,
                      savedErrno ? strerror(savedErrno) : "none",
                      queuedError ? ERR_error_string(queuedError, NULL) : "none",
                      SSL_get_shutdown(_tls));
            [self scheduleSecureTransportFailure];
        }
        break;
    }
    [self flushTLSCiphertext];
}

- (void)receiveTLSCiphertext:(const uint8_t *)data length:(size_t)length {
    if (!_tls || _transportFailed || !data || !length) return;
    BIO *incoming = SSL_get_rbio(_tls);
    if (BIO_write(incoming, data, (int)length) != (int)length) {
        rdp_error("RDPUDP2 TLS input BIO rejected %zu bytes", length);
        [self scheduleSecureTransportFailure];
        return;
    }
    [self pumpTLS];
}

- (BOOL)sendTLSPlaintext:(const uint8_t *)data length:(size_t)length {
    if (!_tlsReady || _transportFailed || !data || !length ||
        length > INT_MAX)
        return NO;
    size_t offset = 0;
    while (offset < length) {
        size_t chunk = MIN(length - offset, (size_t)16384);
        size_t written = 0;
        int rc = SSL_write_ex(_tls, data + offset, chunk, &written);
        if (rc != 1 || written == 0) {
            int error = SSL_get_error(_tls, rc);
            if (error == SSL_ERROR_WANT_WRITE) {
                [self flushTLSCiphertext];
                continue;
            }
            rdp_error("RDPUDP2 TLS write failed after %zu/%zu bytes (SSL %d)",
                      offset, length, error);
            [self scheduleSecureTransportFailure];
            return NO;
        }
        offset += written;
        [self flushTLSCiphertext];
    }
    return YES;
}

- (BOOL)handleRDPEMTFrame:(const RDPEMTFrame *)frame {
    if (!frame || !_activeBootstrap || _transportFailed) return NO;
    if (!_tunnelCreated) {
        BOOL valid = rdpemt_validate_create_request(
            frame, _activeBootstrap.requestID, _activeBootstrap.cookie.bytes);
        uint8_t response[8];
        size_t responseLength = 0;
        uint32_t result = valid ? 0u : 0x80070005u; /* E_ACCESSDENIED */
        if (!rdpemt_encode_create_response(result, response, &responseLength) ||
            ![self sendTLSPlaintext:response length:responseLength])
            return NO;
        if (!valid) {
            rdp_error("RDPEMT CreateRequest rejected: request ID or cookie mismatch");
            return NO;
        }
        @synchronized(self) { _tunnelCreated = YES; }
        rdp_info("RDPEMT reliable UDP tunnel authenticated and created (request %u)",
                 _activeBootstrap.requestID);
        id session = _activeBootstrap.session;
        if ([session respondsToSelector:@selector(udpTunnelDidBecomeReady)])
            [session udpTunnelDidBecomeReady];
        return YES;
    }
    if (frame->action != RDPEMT_ACTION_DATA || frame->flags != 0) {
        rdp_error("unexpected RDPEMT action=%u flags=0x%x after tunnel creation",
                  frame->action, frame->flags);
        return NO;
    }
    rdp_debug("RDPEMT dynamic-channel payload rx: %u bytes",
              frame->payload_length);
    if (frame->payload_length == 0) {
        rdp_debug("RDPEMT control-only DATA received (%zu subheader bytes)",
                  frame->subheaders_length);
        return YES;
    }
    id session = _activeBootstrap.session;
    NSData *payload = [NSData dataWithBytes:frame->payload
                                     length:frame->payload_length];
    if (![session respondsToSelector:@selector(receiveUdpDynamicChannelData:)] ||
        ![session receiveUdpDynamicChannelData:payload]) {
        rdp_error("RDPEMT DVC payload rejected before/after Soft-Sync (%u bytes)",
                  frame->payload_length);
        return NO;
    }
    return YES;
}

- (BOOL)sendDynamicChannelData:(NSData *)data forSession:(id)session {
    if (!data.length || data.length > UINT16_MAX || !session) return NO;
    NSMutableData *frame = [NSMutableData dataWithLength:data.length + 4u];
    size_t encodedLength = 0;
    if (!rdpemt_encode_data(data.bytes, data.length, frame.mutableBytes,
                            frame.length, &encodedLength))
        return NO;
    frame.length = encodedLength;

    @synchronized(self) {
        if (_transportFailed || !_tunnelCreated ||
            !_activeBootstrap.session || _activeBootstrap.session != session)
            return NO;
        /* Keep latency bounded.  The reliable UDP window already holds up to
         * roughly 5 MB; accepting another 64 MB here turned congestion into
         * many seconds of stale desktop data.  Returning NO lets the existing
         * GFX coalescing path drop an intermediate frame and retain latest state. */
        static const NSUInteger kMaxQueuedPlaintext = 4u * 1024u * 1024u;
        if ((_pendingDVCSession && _pendingDVCSession != session) ||
            _pendingDVCPlaintext.length + frame.length > kMaxQueuedPlaintext)
            return NO;
        _pendingDVCSession = session;
        [_pendingDVCPlaintext appendData:frame];
    }
    [self scheduleDynamicChannelDrainIfNeeded];
    return YES;
}

- (void)scheduleDynamicChannelDrainIfNeeded {
    BOOL schedule = NO;
    @synchronized(self) {
        if (_pendingDVCPlaintext.length && !_dvcDrainScheduled) {
            _dvcDrainScheduled = YES;
            schedule = YES;
        }
    }
    if (schedule) {
        __weak typeof(self) weakSelf = self;
        dispatch_async(_queue, ^{ [weakSelf drainPendingDynamicChannelData]; });
    }
}

- (void)drainPendingDynamicChannelData {
    NSData *batch = nil;
    id session = nil;
    static const NSUInteger kDrainChunk = 256u * 1024u;
    static const NSUInteger kMaxPendingTLSCiphertext = 512u * 1024u;

    [self flushTLSCiphertext];
    if (_pendingTLSCiphertext.length >= kMaxPendingTLSCiphertext) {
        /* Leave plaintext queued. ACK/timer processing will resume this drain
         * after ciphertext has entered the reliable packet window. */
        @synchronized(self) { _dvcDrainScheduled = NO; }
        return;
    }

    @synchronized(self) {
        session = _pendingDVCSession;
        NSUInteger count = MIN(_pendingDVCPlaintext.length, kDrainChunk);
        if (count) {
            batch = [_pendingDVCPlaintext subdataWithRange:NSMakeRange(0, count)];
            [_pendingDVCPlaintext replaceBytesInRange:NSMakeRange(0, count)
                                             withBytes:NULL length:0];
        } else {
            _pendingDVCSession = nil;
            _dvcDrainScheduled = NO;
        }
    }
    if (!batch.length) return;
    if (!_tunnelCreated || !_activeBootstrap.session ||
        _activeBootstrap.session != session) {
        rdp_error("discarding %lu queued DVC bytes for an inactive UDP tunnel",
                  (unsigned long)batch.length);
        @synchronized(self) {
            [_pendingDVCPlaintext setLength:0];
            _pendingDVCSession = nil;
            _dvcDrainScheduled = NO;
        }
        return;
    }
    if (![self sendTLSPlaintext:batch.bytes length:batch.length]) {
        rdp_error("failed to send %lu bytes of RDPEMT DVC plaintext",
                  (unsigned long)batch.length);
        [self scheduleSecureTransportFailure];
        return;
    }

    BOOL scheduleMore = NO;
    @synchronized(self) {
        if (_pendingDVCPlaintext.length) {
            scheduleMore = YES;
        } else {
            _pendingDVCSession = nil;
            _dvcDrainScheduled = NO;
        }
    }
    if (scheduleMore) {
        __weak typeof(self) weakSelf = self;
        dispatch_async(_queue, ^{ [weakSelf drainPendingDynamicChannelData]; });
    }
}

- (void)serviceTransportTimers {
    uint64_t now = monotonic_milliseconds();
    if (_awaitingFinalAck && _pendingSynAck.length &&
        now - _synAckSentAtMS >= 300u) {
        if (_synAckRetransmits >= 5u) {
            rdp_error("RDPUDP handshake timed out waiting for final ACK");
            _awaitingFinalAck = NO;
            _pendingSynAck = nil;
            _haveActivePeer = NO;
            _usingRdpUdp2 = NO;
            [self resetSecureTransport];
            return;
        }
        ssize_t sent = sendto(_udpFd, _pendingSynAck.bytes,
                              _pendingSynAck.length, 0,
                              (const struct sockaddr *)&_activePeer,
                              _activePeerLength);
        if (sent == (ssize_t)_pendingSynAck.length) {
            _synAckRetransmits++;
            _synAckSentAtMS = now;
            rdp_debug("RDPUDP SYN+ACK retransmit %u/5",
                      _synAckRetransmits);
        } else {
            rdp_error("RDPUDP SYN+ACK retransmit failed: %s",
                      strerror(errno));
        }
    }
    if (!_udp2) return;
    if (!rdpudp2_transport_tick(_udp2, now)) {
        RDPUDP2Stats stats;
        rdpudp2_transport_get_stats(_udp2, &stats);
        rdp_error("RDPUDP2 transport timed out (rx=%llu tx=%llu retransmit=%llu)",
                  (unsigned long long)stats.datagrams_received,
                  (unsigned long long)stats.datagrams_sent,
                  (unsigned long long)stats.datagrams_retransmitted);
        [self scheduleSecureTransportFailure];
        return;
    }
    [self flushTLSCiphertext];
    [self scheduleDynamicChannelDrainIfNeeded];

    if (_tunnelCreated &&
        (!_lastStatsLogMS || now - _lastStatsLogMS >= 2000u)) {
        RDPUDP2Stats stats;
        rdpudp2_transport_get_stats(_udp2, &stats);
        NSUInteger pendingDVC = 0;
        @synchronized(self) { pendingDVC = _pendingDVCPlaintext.length; }
        const NSUInteger pendingTLS = _pendingTLSCiphertext.length;
        rdp_info("RDPUDP2 stats: datagrams tx=%llu rx=%llu retransmit=%llu "
                 "(fast=%llu timeout=%llu) loss=%llu "
                 "acks tx=%llu delayed=%llu rx=%llu ackvec tx=%llu rx=%llu "
                 "stream tx=%llu rx=%llu inflight=%zu peak=%zu "
                 "srtt=%ums rto=%ums cwnd=%.2f reorder=%llu duplicate=%llu "
                 "malformed=%llu queued tls=%lu dvc=%lu",
                 (unsigned long long)stats.datagrams_sent,
                 (unsigned long long)stats.datagrams_received,
                 (unsigned long long)stats.datagrams_retransmitted,
                 (unsigned long long)stats.fast_retransmissions,
                 (unsigned long long)stats.timeout_retransmissions,
                 (unsigned long long)stats.loss_events,
                 (unsigned long long)stats.acknowledgements_sent,
                 (unsigned long long)stats.delayed_acknowledgements_sent,
                 (unsigned long long)stats.acknowledgements_received,
                 (unsigned long long)stats.acknowledgement_vectors_sent,
                 (unsigned long long)stats.acknowledgement_vectors_received,
                 (unsigned long long)stats.stream_bytes_accepted,
                 (unsigned long long)stats.stream_bytes_delivered,
                 stats.inflight_packets, stats.peak_inflight_packets,
                 stats.smoothed_rtt_ms, stats.retransmit_timeout_ms,
                 stats.congestion_window_packets,
                 (unsigned long long)stats.out_of_order_data,
                 (unsigned long long)stats.duplicate_data,
                 (unsigned long long)stats.malformed_datagrams,
                 (unsigned long)pendingTLS,
                 (unsigned long)pendingDVC);
        void (^metricsHandler)(id, const RDPUDP2Stats *, uint64_t, uint32_t) =
            self.metricsHandler;
        id metricsSession = _activeBootstrap.session;
        if (metricsHandler && metricsSession) {
            const uint64_t queued = (uint64_t)pendingTLS + pendingDVC;
            metricsHandler(metricsSession, &stats, now,
                           queued > UINT32_MAX ? UINT32_MAX
                                               : (uint32_t)queued);
        }
        _lastStatsLogMS = now;
    }
}

- (void)dealloc {
    [self stop];
}

- (void)registerRequestID:(uint32_t)requestID
           securityCookie:(NSData *)securityCookie
                forSession:(id)session {
    if (securityCookie.length != 16 || !session) return;
    NSData *cookieCopy = [securityCookie copy];
    dispatch_async(_queue, ^{
        uint8_t digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(cookieCopy.bytes, (CC_LONG)cookieCopy.length, digest);
        NSData *hash = [NSData dataWithBytes:digest length:sizeof(digest)];
        RDPUDPBootstrapRecord *record = [RDPUDPBootstrapRecord new];
        record.requestID = requestID;
        record.cookie = cookieCopy;
        record.session = session;
        self->_bootstrapsByHash[hash] = record;
        rdp_info("registered TCP multitransport request %u for UDP cookie "
                 "binding (hash=%02x%02x%02x%02x%02x%02x%02x%02x...)",
                 requestID, digest[0], digest[1], digest[2], digest[3],
                 digest[4], digest[5], digest[6], digest[7]);
    });
}

- (void)unregisterSession:(id)session {
    if (!session) return;
    dispatch_async(_queue, ^{
        NSArray<NSData *> *keys = [self->_bootstrapsByHash allKeys];
        for (NSData *key in keys) {
            RDPUDPBootstrapRecord *record = self->_bootstrapsByHash[key];
            if (!record.session || record.session == session)
                [self->_bootstrapsByHash removeObjectForKey:key];
        }
        if (!self->_activeBootstrap.session ||
            self->_activeBootstrap.session == session) {
            BOOL activeSessionEnded = self->_activeBootstrap.session == session;
            self->_activeBootstrap = nil;
            if (activeSessionEnded) {
                [self resetSecureTransport];
                self->_usingRdpUdp2 = NO;
                self->_awaitingFinalAck = NO;
                self->_pendingSynAck = nil;
                self->_haveActivePeer = NO;
            }
        }
    });
}

- (void)receiveAvailableDatagrams {
    for (;;) {
        uint8_t packet[2048];
        struct sockaddr_storage peer = {0};
        socklen_t peerLength = sizeof(peer);
        ssize_t length = recvfrom(_udpFd, packet, sizeof(packet), 0,
                                  (struct sockaddr *)&peer, &peerLength);
        if (length < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EBADF)
                rdp_error("UDP probe recvfrom failed: %s", strerror(errno));
            return;
        }
        if (length == 0) continue;
        _receivedPackets++;
        [self handlePacket:packet length:(size_t)length
                      peer:(const struct sockaddr *)&peer peerLength:peerLength];
    }
}

- (void)handlePacket:(const uint8_t *)packet
               length:(size_t)length
                 peer:(const struct sockaddr *)peer
           peerLength:(socklen_t)peerLength {
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    peer_text(peer, peerLength, host, service);

    /* Versions 1 and 2 finish the legacy three-way handshake with an ACK.
     * Version 3 switches to MS-RDPEUDP2 immediately after SYN+ACK and does not
     * send that legacy ACK. A retransmitted SYN remains recognisable after the
     * switch. */
    RDPUDPBootstrapSyn syn = {0};
    BOOL looksLikeV1Syn = rdpudp_bootstrap_decode_client_syn(
        packet, length, &syn);
    BOOL finalBootstrapAck = !looksLikeV1Syn && _haveActivePeer &&
        peer_matches(&_activePeer, _activePeerLength, peer, peerLength) &&
        rdpudp_bootstrap_decode_final_ack(packet, length,
                                          _serverInitialSequence);
    if (finalBootstrapAck && (_awaitingFinalAck || _usingRdpUdp2)) {
        if (_awaitingFinalAck) {
            _awaitingFinalAck = NO;
            _pendingSynAck = nil;
            _synAckRetransmits = 0;
            rdp_info("RDPUDP three-way handshake complete with %s:%s",
                     host, service);
            if (_negotiatedVersion == RDPUDP_BOOTSTRAP_VERSION_3 &&
                env_enabled("RDP_UDP_FULL_STACK")) {
                if ([self startSecureTransportWithSendMTU:_negotiatedSendMtu
                                               receiveMTU:_negotiatedReceiveMtu]) {
                    _usingRdpUdp2 = YES;
                } else {
                    _usingRdpUdp2 = NO;
                    rdp_error("RDPUDP2 secure transport could not start for %s:%s",
                              host, service);
                }
            } else {
                _usingRdpUdp2 =
                    _negotiatedVersion == RDPUDP_BOOTSTRAP_VERSION_3;
            }
        } else {
            rdp_debug("ignoring duplicate RDPUDP final ACK from %s:%s",
                      host, service);
        }
        return;
    }
    if (_usingRdpUdp2 && !looksLikeV1Syn) {
        if (!peer_matches(&_activePeer, _activePeerLength,
                          peer, peerLength)) {
            rdp_debug("dropping RDPUDP2 datagram from non-active peer %s:%s",
                      host, service);
            return;
        }
        [self logRdpUdp2Packet:packet length:length host:host service:service];
        if (_udp2 && !rdpudp2_transport_receive(
                         _udp2, packet, length, monotonic_milliseconds()))
            rdp_error("RDPUDP2 packet from %s:%s failed validation", host, service);
        return;
    }

    if (length < 8) {
        rdp_info("UDP probe rx #%llu %s:%s len=%zu (too short)",
                 (unsigned long long)_receivedPackets, host, service, length);
        return;
    }

    if (!looksLikeV1Syn) {
        if (length >= 8) {
            rdp_info("invalid/non-SYN RDPUDP1 rx #%llu %s:%s len=%zu "
                     "flags=0x%04x ack=%u window=%u",
                     (unsigned long long)_receivedPackets, host, service,
                     length, read_be16(packet + 6), read_be32(packet),
                     read_be16(packet + 4));
        } else {
            rdp_info("UDP probe rx #%llu %s:%s len=%zu (too short)",
                     (unsigned long long)_receivedPackets, host, service, length);
        }
        return;
    }

    uint32_t clientInitial = syn.initial_sequence;
    uint16_t upstreamMtu = syn.upstream_mtu;
    uint16_t downstreamMtu = syn.downstream_mtu;
    uint16_t flags = syn.flags;
    uint16_t synexFlags = syn.synex_flags;
    uint16_t offeredVersion = syn.offered_version;
    const uint8_t *cookieHash = syn.cookie_hash_present
                                    ? syn.cookie_hash : NULL;

    /* This implementation carries the reliable RDPEUDP2 transport only.
     * Recognising SYNLOSSY in the bootstrap decoder is useful for diagnostics,
     * but accepting it here would advertise a transport we do not implement.
     * Likewise, the secure tunnel below depends on the v3 cookie binding. */
    if (env_enabled("RDP_UDP_FULL_STACK") &&
        ((flags & RDPUDP_BOOTSTRAP_FLAG_SYNLOSSY) != 0 ||
         !syn.version_present ||
         offeredVersion != RDPUDP_BOOTSTRAP_VERSION_3)) {
        rdp_error("RDPUDP SYN from %s:%s rejected: reliable version 3 is "
                  "required (flags=0x%04x version=0x%04x)",
                  host, service, flags, offeredVersion);
        return;
    }

    char hashPrefix[17] = "none";
    if (cookieHash) {
        snprintf(hashPrefix, sizeof(hashPrefix),
                 "%02x%02x%02x%02x%02x%02x%02x%02x",
                 cookieHash[0], cookieHash[1], cookieHash[2], cookieHash[3],
                 cookieHash[4], cookieHash[5], cookieHash[6], cookieHash[7]);
    }
    rdp_info("RDPUDP SYN rx #%llu %s:%s len=%zu flags=0x%04x initial=%u "
             "window=%u mtu(up=%u down=%u) synex=0x%04x version=0x%04x "
             "cookieHash=%s%s",
             (unsigned long long)_receivedPackets, host, service, length, flags,
             clientInitial, syn.receive_window, upstreamMtu, downstreamMtu,
             synexFlags, offeredVersion, hashPrefix,
             cookieHash ? "..." : "");

    /* The full secure transport will compare this hash with SHA-256 of the
     * exact 16-byte cookie FreeRDP sent on TCP.  Probe mode is isolated and
     * only records it; it must never be enabled on the stable endpoint. */
    if (!cookieHash && offeredVersion == RDPUDP_BOOTSTRAP_VERSION_3)
        rdp_error("RDPUDP v3 client omitted the multitransport cookie hash");

    RDPUDPBootstrapRecord *bootstrap = nil;
    NSData *matchedHashKey = nil;
    BOOL usedWordSwap = NO;
    if (cookieHash) {
        NSData *hash = [NSData dataWithBytes:cookieHash length:CC_SHA256_DIGEST_LENGTH];
        bootstrap = _bootstrapsByHash[hash];
        if (bootstrap) matchedHashKey = hash;
        if (!bootstrap) {
            for (NSData *expectedHash in _bootstrapsByHash) {
                bool swapped = false;
                if (expectedHash.length == CC_SHA256_DIGEST_LENGTH &&
                    rdpudp_bootstrap_cookie_hash_matches(
                        cookieHash, expectedHash.bytes, &swapped)) {
                    bootstrap = _bootstrapsByHash[expectedHash];
                    matchedHashKey = expectedHash;
                    usedWordSwap = swapped ? YES : NO;
                    break;
                }
            }
        }
        if (bootstrap && !bootstrap.session) {
            [_bootstrapsByHash removeObjectForKey:matchedHashKey];
            bootstrap = nil;
        }
    }
    if ((env_enabled("RDP_UDP_REQUIRE_COOKIE") ||
         env_enabled("RDP_UDP_FULL_STACK")) && !bootstrap) {
        rdp_error("RDPUDP v3 SYN from %s:%s rejected: cookie hash is not bound "
                  "to a live TCP peer", host, service);
        return;
    }
    id previousSession = _activeBootstrap.session;
    BOOL previousTunnelCreated = _tunnelCreated;
    BOOL retransmittedSyn = _haveActivePeer &&
                            peer_matches(&_activePeer, _activePeerLength,
                                         peer, peerLength) &&
                            _clientInitialSequence == clientInitial;
    if (!retransmittedSyn) {
        [self resetSecureTransport];
        _activeBootstrap = nil;
        _awaitingFinalAck = NO;
        _usingRdpUdp2 = NO;
        _pendingSynAck = nil;
        _synAckRetransmits = 0;
        if (previousTunnelCreated &&
            [previousSession respondsToSelector:@selector(udpTunnelDidFail)])
            [previousSession udpTunnelDidFail];
    }
    if (bootstrap) {
        _activeBootstrap = bootstrap;
        rdp_info("RDPUDP SYN securely matched TCP multitransport request %u%s",
                 bootstrap.requestID,
                 usedWordSwap ? " using network-DWORD hash normalization" : "");
    }
    _activePeerLength = MIN(peerLength, (socklen_t)sizeof(_activePeer));
    memcpy(&_activePeer, peer, _activePeerLength);
    _haveActivePeer = YES;
    _clientInitialSequence = clientInitial;
    if (!retransmittedSyn)
        _serverInitialSequence = arc4random();
    _negotiatedVersion = (offeredVersion == RDPUDP_BOOTSTRAP_VERSION_3)
                             ? RDPUDP_BOOTSTRAP_VERSION_3
                             : offeredVersion;
    /* The MTU fields describe the sender named by the field, not the local
     * socket direction.  Our upstream (server -> client) is bounded by the
     * client's downstream, and our downstream by the client's upstream. */
    uint16_t serverUpstreamMtu = downstreamMtu;
    uint16_t serverDownstreamMtu = upstreamMtu;
    _negotiatedSendMtu = serverUpstreamMtu;
    _negotiatedReceiveMtu = serverDownstreamMtu;
    _negotiatedMtu = MIN(serverUpstreamMtu, serverDownstreamMtu);

    uint8_t response[RDPUDP_BOOTSTRAP_MAX_MTU] = {0};
    size_t responseLength = 0;
    if (!rdpudp_bootstrap_encode_syn_ack(
            &syn, _serverInitialSequence, 4096, serverUpstreamMtu,
            serverDownstreamMtu, _negotiatedVersion,
            response, &responseLength)) {
        rdp_error("failed to encode RDPUDP SYN+ACK for %s:%s", host, service);
        return;
    }
    uint16_t responseFlags = read_be16(response + 6);
    ssize_t sent = sendto(_udpFd, response, responseLength, 0, peer, peerLength);
    if (sent < 0) {
        rdp_error("RDPUDP SYN+ACK send to %s:%s failed: %s",
                  host, service, strerror(errno));
        return;
    }
    rdp_info("RDPUDP SYN+ACK tx %s:%s len=%zd flags=0x%04x initial=%u "
             "ack=%u mtu(up=%u down=%u) version=0x%04x",
             host, service, sent, responseFlags, _serverInitialSequence,
             clientInitial, serverUpstreamMtu, serverDownstreamMtu,
             _negotiatedVersion);

    if (_negotiatedVersion == RDPUDP_BOOTSTRAP_VERSION_3 &&
        env_enabled("RDP_UDP_FULL_STACK") && !_usingRdpUdp2) {
        _awaitingFinalAck = NO;
        _pendingSynAck = nil;
        _synAckRetransmits = 0;
        if ([self startSecureTransportWithSendMTU:_negotiatedSendMtu
                                       receiveMTU:_negotiatedReceiveMtu]) {
            _usingRdpUdp2 = YES;
            rdp_info("RDPUDP v3 initialization complete; switched directly "
                     "to RDPUDP2 after SYN+ACK");
        } else {
            _usingRdpUdp2 = NO;
            rdp_error("RDPUDP2 secure transport could not start for %s:%s",
                      host, service);
        }
    } else if (!env_enabled("RDP_UDP_FULL_STACK")) {
        _usingRdpUdp2 =
            _negotiatedVersion == RDPUDP_BOOTSTRAP_VERSION_3;
    }
}

- (void)logRdpUdp2Packet:(const uint8_t *)packet
                   length:(size_t)length
                     host:(const char *)host
                  service:(const char *)service {
    BOOL sampled = !env_enabled("RDP_UDP_FULL_STACK") ||
                   _receivedPackets <= 12u ||
                   (_receivedPackets % 1024u) == 0u;
    if (!sampled) return;
    if (length < 8) {
        rdp_debug("RDPUDP2 rx #%llu %s:%s len=%zu (short)",
                  (unsigned long long)_receivedPackets, host, service, length);
        return;
    }

    /* MS-RDPEUDP2 moves PacketPrefixByte from logical byte 0 to wire offset 7.
     * Logical flag bytes 1..2 stay at wire offsets 1..2; wire byte 0 moves to
     * logical offset 7. Undo just enough to expose flags and packet type. */
    uint8_t prefix = packet[7];
    uint16_t header = read_le16(packet + 1);
    uint16_t flags = header & 0x0fffu;
    uint8_t logWindow = (uint8_t)(header >> 12);
    uint8_t packetType = (prefix & 0x1e) >> 1;
    BOOL hasAck = (flags & 0x0001) != 0;
    BOOL hasData = (flags & 0x0004) != 0;
    BOOL hasAckVector = (flags & 0x0008) != 0;
    BOOL tlsLike = NO;

    /* We intentionally do not attempt full variable-header decoding here.
     * During the live probe the packet bytes are retained only in aggregate
     * logs; the next transport layer will parse/ACK them with tested state. */
    for (size_t i = 9; i + 4 < length && i < 96; i++) {
        if (packet[i] >= 0x14 && packet[i] <= 0x17 && packet[i + 1] == 0x03) {
            tlsLike = YES;
            break;
        }
    }
    uint16_t compatibilityFlags = flags & 0x0200u;
    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet decoded = {0};
    BOOL decodedOK = rdpudp2_decode(packet, length, logical, &decoded);
    rdp_info("RDPUDP2 rx #%llu %s:%s len=%zu prefix=0x%02x type=%u "
             "flags=0x%03x compat=0x%03x log-window=%u ack=%d data=%d "
             "ackvec=%d data-seq=%u channel-seq=%u aoa=%u decoded=%d "
             "tls-like=%d mtu=%u",
             (unsigned long long)_receivedPackets, host, service, length,
             prefix, packetType, flags, compatibilityFlags, logWindow, hasAck,
             hasData, hasAckVector, decoded.data_sequence,
             decoded.channel_sequence, decoded.ack_of_acks_sequence,
             decodedOK, tlsLike, _negotiatedMtu);

    if (env_enabled("RDP_UDP_HEXDUMP")) {
        char line[3 * 32 + 1] = {0};
        size_t count = MIN(length, (size_t)32);
        for (size_t i = 0; i < count; i++)
            snprintf(line + i * 3, sizeof(line) - i * 3, "%02x%s",
                     packet[i], (i + 1 == count) ? "" : " ");
        rdp_debug("RDPUDP2 first %zu bytes: %s", count, line);
    }
}

@end
