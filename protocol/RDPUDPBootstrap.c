#include "protocol/RDPUDPBootstrap.h"

#include <string.h>

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void write_be16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write_be32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static bool valid_mtu(uint16_t mtu) {
    return mtu >= RDPUDP_BOOTSTRAP_MIN_MTU &&
           mtu <= RDPUDP_BOOTSTRAP_MAX_MTU;
}

static bool all_zero(const uint8_t *data, size_t length) {
    uint8_t combined = 0;
    for (size_t i = 0; i < length; ++i) combined |= data[i];
    return combined == 0;
}

bool rdpudp_bootstrap_decode_client_syn(const uint8_t *datagram, size_t length,
                                        RDPUDPBootstrapSyn *syn) {
    if (!datagram || !syn || length < 16u ||
        length > RDPUDP_BOOTSTRAP_MAX_MTU)
        return false;
    memset(syn, 0, sizeof(*syn));
    syn->source_ack = read_be32(datagram);
    syn->receive_window = read_be16(datagram + 4);
    syn->flags = read_be16(datagram + 6);
    syn->initial_sequence = read_be32(datagram + 8);
    syn->upstream_mtu = read_be16(datagram + 12);
    syn->downstream_mtu = read_be16(datagram + 14);

    const uint16_t allowed = RDPUDP_BOOTSTRAP_FLAG_SYN |
                             RDPUDP_BOOTSTRAP_FLAG_SYNLOSSY |
                             RDPUDP_BOOTSTRAP_FLAG_CORRELATION_ID |
                             RDPUDP_BOOTSTRAP_FLAG_SYNEX;
    if (!(syn->flags & RDPUDP_BOOTSTRAP_FLAG_SYN) ||
        (syn->flags & ~allowed) != 0 || syn->source_ack != UINT32_MAX ||
        syn->receive_window == 0 || !valid_mtu(syn->upstream_mtu) ||
        !valid_mtu(syn->downstream_mtu) ||
        length != (syn->upstream_mtu < syn->downstream_mtu
                       ? syn->upstream_mtu : syn->downstream_mtu))
        return false;

    size_t cursor = 16u;
    if (syn->flags & RDPUDP_BOOTSTRAP_FLAG_CORRELATION_ID) {
        if (cursor + RDPUDP_BOOTSTRAP_CORRELATION_LENGTH > length) return false;
        memcpy(syn->correlation, datagram + cursor,
               RDPUDP_BOOTSTRAP_CORRELATION_LENGTH);
        if (!all_zero(syn->correlation + 16u, 16u)) return false;
        syn->correlation_present = true;
        cursor += RDPUDP_BOOTSTRAP_CORRELATION_LENGTH;
    }

    if (syn->flags & RDPUDP_BOOTSTRAP_FLAG_SYNEX) {
        if (cursor + 2u > length) return false;
        syn->synex_flags = read_be16(datagram + cursor);
        cursor += 2u;
        if ((syn->synex_flags & ~RDPUDP_BOOTSTRAP_SYNEX_VERSION_INFO) != 0)
            return false;
        if (syn->synex_flags & RDPUDP_BOOTSTRAP_SYNEX_VERSION_INFO) {
            if (cursor + 2u > length) return false;
            syn->offered_version = read_be16(datagram + cursor);
            syn->version_present = true;
            cursor += 2u;
            if (syn->offered_version == RDPUDP_BOOTSTRAP_VERSION_3) {
                if (cursor + RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH > length)
                    return false;
                memcpy(syn->cookie_hash, datagram + cursor,
                       RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH);
                syn->cookie_hash_present = true;
                cursor += RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH;
            }
        }
    }

    return cursor <= length && all_zero(datagram + cursor, length - cursor);
}

bool rdpudp_bootstrap_cookie_hash_matches(
    const uint8_t wire_hash[RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH],
    const uint8_t digest[RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH],
    bool *used_word_swap) {
    if (used_word_swap) *used_word_swap = false;
    if (!wire_hash || !digest) return false;

    uint8_t direct_difference = 0;
    uint8_t word_difference = 0;
    for (size_t i = 0; i < RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH; ++i) {
        direct_difference |= wire_hash[i] ^ digest[i];
        const size_t word_base = i & ~(size_t)3u;
        const size_t reversed = word_base + (3u - (i & 3u));
        word_difference |= wire_hash[i] ^ digest[reversed];
    }
    const bool direct = direct_difference == 0;
    const bool word_swapped = word_difference == 0;
    if (used_word_swap) *used_word_swap = !direct && word_swapped;
    return direct || word_swapped;
}

bool rdpudp_bootstrap_encode_syn_ack(
    const RDPUDPBootstrapSyn *client, uint32_t server_initial_sequence,
    uint16_t receive_window, uint16_t send_mtu, uint16_t receive_mtu,
    uint16_t negotiated_version,
    uint8_t datagram[RDPUDP_BOOTSTRAP_MAX_MTU], size_t *length) {
    if (!client || !datagram || !length || receive_window == 0 ||
        !valid_mtu(send_mtu) || !valid_mtu(receive_mtu))
        return false;
    size_t datagram_length = send_mtu < receive_mtu ? send_mtu : receive_mtu;
    memset(datagram, 0, datagram_length);
    uint16_t flags = RDPUDP_BOOTSTRAP_FLAG_SYN | RDPUDP_BOOTSTRAP_FLAG_ACK;
    size_t cursor = 16u;

    write_be32(datagram, client->initial_sequence);
    write_be16(datagram + 4, receive_window);
    write_be32(datagram + 8, server_initial_sequence);
    write_be16(datagram + 12, send_mtu);
    write_be16(datagram + 14, receive_mtu);
    /* Correlation IDs are client-to-server metadata.  A server SYN+ACK does
     * not echo the client's value (the Microsoft wire example omits it even
     * when the initiating SYN includes it). */
    if ((client->flags & RDPUDP_BOOTSTRAP_FLAG_SYNEX) &&
        client->version_present) {
        if (cursor + 4u > datagram_length) return false;
        flags |= RDPUDP_BOOTSTRAP_FLAG_SYNEX;
        write_be16(datagram + cursor, RDPUDP_BOOTSTRAP_SYNEX_VERSION_INFO);
        write_be16(datagram + cursor + 2u, negotiated_version);
        cursor += 4u;
    }
    write_be16(datagram + 6, flags);
    *length = datagram_length;
    return cursor <= datagram_length;
}

bool rdpudp_bootstrap_decode_final_ack(const uint8_t *datagram, size_t length,
                                       uint32_t server_initial_sequence) {
    /* The final handshake ACK carries an empty, DWORD-aligned ACK vector:
     * 8-byte FEC header + 2-byte vector size + 2 bytes zero padding. */
    return datagram && length == 12u &&
           read_be32(datagram) == server_initial_sequence &&
           read_be16(datagram + 4) != 0 &&
           read_be16(datagram + 6) == RDPUDP_BOOTSTRAP_FLAG_ACK &&
           read_be16(datagram + 8) == 0 &&
           datagram[10] == 0 && datagram[11] == 0;
}
