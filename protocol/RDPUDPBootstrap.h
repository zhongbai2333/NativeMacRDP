#ifndef MACOS_RDP_UDP_BOOTSTRAP_H
#define MACOS_RDP_UDP_BOOTSTRAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RDPUDP_BOOTSTRAP_MIN_MTU 1132u
#define RDPUDP_BOOTSTRAP_MAX_MTU 1232u
#define RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH 32u
#define RDPUDP_BOOTSTRAP_CORRELATION_LENGTH 32u

enum {
    RDPUDP_BOOTSTRAP_FLAG_SYN = 0x0001,
    RDPUDP_BOOTSTRAP_FLAG_ACK = 0x0004,
    RDPUDP_BOOTSTRAP_FLAG_SYNLOSSY = 0x0200,
    RDPUDP_BOOTSTRAP_FLAG_CORRELATION_ID = 0x0800,
    RDPUDP_BOOTSTRAP_FLAG_SYNEX = 0x1000,
    RDPUDP_BOOTSTRAP_SYNEX_VERSION_INFO = 0x0001,
    RDPUDP_BOOTSTRAP_VERSION_1 = 0x0001,
    RDPUDP_BOOTSTRAP_VERSION_2 = 0x0002,
    RDPUDP_BOOTSTRAP_VERSION_3 = 0x0101,
};

typedef struct {
    uint32_t source_ack;
    uint16_t receive_window;
    uint16_t flags;
    uint32_t initial_sequence;
    uint16_t upstream_mtu;
    uint16_t downstream_mtu;
    bool correlation_present;
    uint8_t correlation[RDPUDP_BOOTSTRAP_CORRELATION_LENGTH];
    bool version_present;
    uint16_t synex_flags;
    uint16_t offered_version;
    bool cookie_hash_present;
    uint8_t cookie_hash[RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH];
} RDPUDPBootstrapSyn;

/* Strictly decodes a client SYN, including required zero padding. */
bool rdpudp_bootstrap_decode_client_syn(const uint8_t *datagram, size_t length,
                                        RDPUDPBootstrapSyn *syn);

/* Windows describes cookieHash as eight network-order UINT32 values. Accept
 * both the canonical SHA-256 byte string and that DWORD-oriented wire view,
 * comparing every byte in either case. */
bool rdpudp_bootstrap_cookie_hash_matches(
    const uint8_t wire_hash[RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH],
    const uint8_t digest[RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH],
    bool *used_word_swap);

/* Encodes the server SYN+ACK and pads it to min(send_mtu, receive_mtu). */
bool rdpudp_bootstrap_encode_syn_ack(
    const RDPUDPBootstrapSyn *client, uint32_t server_initial_sequence,
    uint16_t receive_window, uint16_t send_mtu, uint16_t receive_mtu,
    uint16_t negotiated_version,
    uint8_t datagram[RDPUDP_BOOTSTRAP_MAX_MTU], size_t *length);

/* Validates the legacy ACK that completes the three-way handshake before v3
 * switches the connection to RDP-UDP2 packets. */
bool rdpudp_bootstrap_decode_final_ack(const uint8_t *datagram, size_t length,
                                       uint32_t server_initial_sequence);

#ifdef __cplusplus
}
#endif

#endif
