#include "protocol/RDPEMT.h"
#include "protocol/RDPUDP2.h"
#include "protocol/RDPUDPBootstrap.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_write_be16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void test_write_be32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint16_t test_read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t test_read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

typedef struct {
    uint8_t datagrams[128][RDPUDP2_MAX_DATAGRAM];
    size_t datagram_lengths[128];
    size_t datagram_count;
    uint8_t delivered[4096];
    size_t delivered_length;
} Capture;

static bool capture_send(void *context, const uint8_t *data, size_t length) {
    Capture *capture = context;
    assert(capture->datagram_count < 128);
    assert(length <= RDPUDP2_MAX_DATAGRAM);
    memcpy(capture->datagrams[capture->datagram_count], data, length);
    capture->datagram_lengths[capture->datagram_count] = length;
    capture->datagram_count++;
    return true;
}

static void capture_deliver(void *context, const uint8_t *data, size_t length) {
    Capture *capture = context;
    assert(length <= sizeof(capture->delivered) - capture->delivered_length);
    memcpy(capture->delivered + capture->delivered_length, data, length);
    capture->delivered_length += length;
}

static size_t encode_data(uint16_t data_sequence, uint16_t channel_sequence,
                          const char *data,
                          uint8_t wire[RDPUDP2_MAX_DATAGRAM]) {
    RDPUDP2Packet packet = {0};
    packet.flags = RDPUDP2_FLAG_DATA;
    packet.log_window_size = 12;
    packet.data_sequence = data_sequence;
    packet.channel_sequence = channel_sequence;
    packet.data = (const uint8_t *)data;
    packet.data_length = strlen(data);
    size_t length = 0;
    assert(rdpudp2_encode(&packet, wire, &length));
    return length;
}

static void test_udp_bootstrap(void) {
    uint8_t syn[RDPUDP_BOOTSTRAP_MAX_MTU] = {0};
    const uint16_t flags = RDPUDP_BOOTSTRAP_FLAG_SYN |
                           RDPUDP_BOOTSTRAP_FLAG_CORRELATION_ID |
                           RDPUDP_BOOTSTRAP_FLAG_SYNEX;
    test_write_be32(syn, UINT32_MAX);
    test_write_be16(syn + 4, 256);
    test_write_be16(syn + 6, flags);
    test_write_be32(syn + 8, UINT32_C(0x11223344));
    test_write_be16(syn + 12, 1132);
    test_write_be16(syn + 14, 1232);
    for (size_t i = 0; i < 16; ++i) syn[16 + i] = (uint8_t)(i + 1u);
    test_write_be16(syn + 48, RDPUDP_BOOTSTRAP_SYNEX_VERSION_INFO);
    test_write_be16(syn + 50, RDPUDP_BOOTSTRAP_VERSION_3);
    for (size_t i = 0; i < RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH; ++i)
        syn[52 + i] = (uint8_t)(0xa0u + i);

    RDPUDPBootstrapSyn parsed;
    assert(rdpudp_bootstrap_decode_client_syn(syn, 1132, &parsed));
    assert(parsed.initial_sequence == UINT32_C(0x11223344));
    assert(parsed.upstream_mtu == 1132);
    assert(parsed.downstream_mtu == 1232);
    assert(parsed.correlation_present);
    assert(parsed.version_present);
    assert(parsed.offered_version == RDPUDP_BOOTSTRAP_VERSION_3);
    assert(parsed.cookie_hash_present);
    assert(memcmp(parsed.cookie_hash, syn + 52,
                  RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH) == 0);

    uint8_t digest[RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH];
    uint8_t word_swapped[RDPUDP_BOOTSTRAP_COOKIE_HASH_LENGTH];
    for (size_t i = 0; i < sizeof(digest); ++i) digest[i] = (uint8_t)i;
    for (size_t word = 0; word < sizeof(digest); word += 4u) {
        word_swapped[word] = digest[word + 3u];
        word_swapped[word + 1u] = digest[word + 2u];
        word_swapped[word + 2u] = digest[word + 1u];
        word_swapped[word + 3u] = digest[word];
    }
    bool used_word_swap = true;
    assert(rdpudp_bootstrap_cookie_hash_matches(digest, digest,
                                                 &used_word_swap));
    assert(!used_word_swap);
    assert(rdpudp_bootstrap_cookie_hash_matches(word_swapped, digest,
                                                 &used_word_swap));
    assert(used_word_swap);
    word_swapped[7] ^= 1u;
    assert(!rdpudp_bootstrap_cookie_hash_matches(word_swapped, digest,
                                                  &used_word_swap));

    uint8_t response[RDPUDP_BOOTSTRAP_MAX_MTU];
    size_t response_length = 0;
    assert(rdpudp_bootstrap_encode_syn_ack(
        &parsed, UINT32_C(0xaabbccdd), 4096, 1232, 1132,
        RDPUDP_BOOTSTRAP_VERSION_3, response, &response_length));
    assert(response_length == 1132);
    assert(test_read_be32(response) == UINT32_C(0x11223344));
    assert(test_read_be16(response + 4) == 4096);
    assert(test_read_be16(response + 6) ==
           (RDPUDP_BOOTSTRAP_FLAG_SYN | RDPUDP_BOOTSTRAP_FLAG_ACK |
            RDPUDP_BOOTSTRAP_FLAG_SYNEX));
    assert(test_read_be32(response + 8) == UINT32_C(0xaabbccdd));
    assert(test_read_be16(response + 12) == 1232);
    assert(test_read_be16(response + 14) == 1132);
    assert(test_read_be16(response + 16) ==
           RDPUDP_BOOTSTRAP_SYNEX_VERSION_INFO);
    assert(test_read_be16(response + 18) == RDPUDP_BOOTSTRAP_VERSION_3);
    for (size_t i = 20; i < response_length; ++i) assert(response[i] == 0);

    uint8_t final_ack[12] = {0};
    test_write_be32(final_ack, UINT32_C(0xaabbccdd));
    test_write_be16(final_ack + 4, 4096);
    test_write_be16(final_ack + 6, RDPUDP_BOOTSTRAP_FLAG_ACK);
    assert(rdpudp_bootstrap_decode_final_ack(
        final_ack, sizeof(final_ack), UINT32_C(0xaabbccdd)));
    assert(!rdpudp_bootstrap_decode_final_ack(
        final_ack, sizeof(final_ack) - 1u, UINT32_C(0xaabbccdd)));
    final_ack[11] = 1;
    assert(!rdpudp_bootstrap_decode_final_ack(
        final_ack, sizeof(final_ack), UINT32_C(0xaabbccdd)));
    final_ack[11] = 0;
    test_write_be16(final_ack + 8, 1);
    assert(!rdpudp_bootstrap_decode_final_ack(
        final_ack, sizeof(final_ack), UINT32_C(0xaabbccdd)));

    syn[100] = 1; /* Padding MUST be zero. */
    assert(!rdpudp_bootstrap_decode_client_syn(syn, 1132, &parsed));
    syn[100] = 0;
    syn[40] = 1; /* Correlation reserved field MUST be zero. */
    assert(!rdpudp_bootstrap_decode_client_syn(syn, 1132, &parsed));
    syn[40] = 0;
    assert(!rdpudp_bootstrap_decode_client_syn(syn, 1131, &parsed));
    test_write_be32(syn, 0); /* A client SYN acknowledges no source packet. */
    assert(!rdpudp_bootstrap_decode_client_syn(syn, 1132, &parsed));
}

static void test_udp2_codec(void) {
    uint8_t body[24];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (uint8_t)(0xa0 + i);

    uint8_t delayed[] = { 3, 4 };
    RDPUDP2Packet packet = {0};
    packet.flags = RDPUDP2_FLAG_ACK | RDPUDP2_FLAG_DATA |
                   RDPUDP2_FLAG_AOA | RDPUDP2_FLAG_DELAY_ACK_INFO;
    packet.log_window_size = 12;
    packet.ack.sequence = 0x1234;
    packet.ack.received_timestamp = 0xabcdef;
    packet.ack.send_gap_ms = 9;
    packet.ack.delayed_count = 2;
    packet.ack.delayed_scale = 1;
    packet.ack.delayed_additions = delayed;
    packet.max_delayed_acks = 8;
    packet.delayed_ack_timeout_ms = 100;
    packet.ack_of_acks_sequence = 0x1122;
    packet.data_sequence = 0x3344;
    packet.channel_sequence = 0x5566;
    packet.data = body;
    packet.data_length = sizeof(body);

    uint8_t wire[RDPUDP2_MAX_DATAGRAM];
    size_t wire_length = 0;
    assert(rdpudp2_encode(&packet, wire, &wire_length));
    assert(wire_length < RDPUDP2_MAX_DATAGRAM);

    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet decoded;
    assert(rdpudp2_decode(wire, wire_length, logical, &decoded));
    assert(decoded.flags == packet.flags);
    assert(decoded.log_window_size == 12);
    assert(decoded.ack.sequence == 0x1234);
    assert(decoded.ack.received_timestamp == 0xabcdef);
    assert(decoded.ack.delayed_count == 2);
    assert(memcmp(decoded.ack.delayed_additions, delayed, sizeof(delayed)) == 0);
    assert(decoded.delayed_ack_timeout_ms == 100);
    assert(decoded.ack_of_acks_sequence == 0x1122);
    assert(decoded.data_sequence == 0x3344);
    assert(decoded.channel_sequence == 0x5566);
    assert(decoded.data_length == sizeof(body));
    assert(memcmp(decoded.data, body, sizeof(body)) == 0);

    /* Current mstsc builds set reserved bit 0x200 without inserting another
     * optional payload. Accept it on input while preserving documented field
     * offsets; the encoder deliberately remains spec-only. */
    wire[2] |= 0x02;
    assert(rdpudp2_decode(wire, wire_length, logical, &decoded));
    assert(decoded.flags == (packet.flags | 0x200));
    assert(decoded.ack.sequence == 0x1234);
    assert(decoded.delayed_ack_timeout_ms == 100);
    assert(decoded.ack_of_acks_sequence == 0x1122);
    assert(decoded.data_sequence == 0x3344);
    assert(decoded.channel_sequence == 0x5566);
    assert(decoded.data_length == sizeof(body));
    assert(memcmp(decoded.data, body, sizeof(body)) == 0);
    wire[2] &= (uint8_t)~0x02u;

    packet.log_window_size = 15;
    assert(rdpudp2_encode(&packet, wire, &wire_length));
    assert(rdpudp2_decode(wire, wire_length, logical, &decoded));
    assert(decoded.log_window_size == 15);

    uint8_t saved_prefix = wire[7];
    wire[7] = saved_prefix | 0x01; /* Reserved prefix bit must be zero. */
    assert(!rdpudp2_decode(wire, wire_length, logical, &decoded));
    wire[7] = (saved_prefix & 0xe1) | (3u << 1); /* Packet type must be 0 or 8. */
    assert(!rdpudp2_decode(wire, wire_length, logical, &decoded));

    /* A short packet cannot use its padding as a missing mandatory field. */
    RDPUDP2Packet empty = {0};
    empty.flags = RDPUDP2_FLAG_DATA;
    empty.log_window_size = 12;
    empty.data_sequence = 1;
    empty.channel_sequence = 1;
    assert(rdpudp2_encode(&empty, wire, &wire_length));
    assert(rdpudp2_decode(wire, wire_length, logical, &decoded));
    wire[7] = (wire[7] & 0x1f) | (2u << 5);
    assert(!rdpudp2_decode(wire, wire_length, logical, &decoded));

    RDPUDP2Packet no_payload = { .log_window_size = 12 };
    assert(!rdpudp2_encode(&no_payload, wire, &wire_length));
    no_payload.flags = 0x002; /* Reserved flag. */
    assert(!rdpudp2_encode(&no_payload, wire, &wire_length));
}

static void test_udp2_reordering(void) {
    Capture capture = {0};
    RDPUDP2Transport *receiver = rdpudp2_transport_new(
        1232, 1232, capture_send, capture_deliver, &capture);
    assert(receiver);

    uint8_t first[RDPUDP2_MAX_DATAGRAM];
    uint8_t second[RDPUDP2_MAX_DATAGRAM];
    uint8_t third[RDPUDP2_MAX_DATAGRAM];
    size_t first_length = encode_data(20, 1, "hello ", first);
    size_t third_length = encode_data(22, 3, "!", third);
    size_t second_length = encode_data(21, 2, "world", second);
    assert(rdpudp2_transport_receive(receiver, first, first_length, 100));
    assert(capture.delivered_length == 6);
    assert(rdpudp2_transport_receive(receiver, third, third_length, 101));
    assert(capture.delivered_length == 6);
    assert(rdpudp2_transport_receive(receiver, second, second_length, 102));
    assert(capture.delivered_length == 12);
    assert(memcmp(capture.delivered, "hello world!", 12) == 0);
    assert(capture.datagram_count == 3);

    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet ack;
    assert(rdpudp2_decode(capture.datagrams[2], capture.datagram_lengths[2],
                          logical, &ack));
    assert((ack.flags & RDPUDP2_FLAG_ACK) != 0);
    assert(ack.ack.sequence == 22);
    assert(ack.ack.received_timestamp == 101u * 250u);
    assert(ack.ack.delayed_count == 1);

    /* A retransmit can use a fresh data sequence while retaining channel seq. */
    size_t duplicate_length = encode_data(23, 2, "world", second);
    assert(rdpudp2_transport_receive(receiver, second, duplicate_length, 127));
    RDPUDP2Stats stats;
    rdpudp2_transport_get_stats(receiver, &stats);
    assert(stats.duplicate_data == 1);
    rdpudp2_transport_free(receiver);
}

static void test_udp2_mstsc_initial_packet_compatibility(void) {
    Capture capture = {0};
    RDPUDP2Transport *transport = rdpudp2_transport_new(
        1232, 1232, capture_send, capture_deliver, &capture);
    assert(transport);

    RDPUDP2Packet client_hello = {0};
    client_hello.flags = RDPUDP2_FLAG_DATA | RDPUDP2_FLAG_AOA |
                         RDPUDP2_FLAG_DELAY_ACK_INFO;
    client_hello.log_window_size = 15;
    client_hello.max_delayed_acks = 1;
    client_hello.delayed_ack_timeout_ms = 20;
    client_hello.ack_of_acks_sequence = 100;
    client_hello.data_sequence = 101;
    client_hello.channel_sequence = 1;
    client_hello.data = (const uint8_t *)"client hello";
    client_hello.data_length = 12;

    uint8_t wire[RDPUDP2_MAX_DATAGRAM];
    size_t wire_length = 0;
    assert(rdpudp2_encode(&client_hello, wire, &wire_length));
    wire[2] |= 0x02; /* mstsc build 26200 compatibility bit 0x200. */
    assert(rdpudp2_transport_receive(transport, wire, wire_length, 100));
    assert(capture.delivered_length == 12);
    assert(memcmp(capture.delivered, "client hello", 12) == 0);
    assert(capture.datagram_count == 1);

    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet ack;
    assert(rdpudp2_decode(capture.datagrams[0], capture.datagram_lengths[0],
                          logical, &ack));
    assert((ack.flags & RDPUDP2_FLAG_ACK) != 0);
    assert(ack.ack.sequence == 101);

    assert(rdpudp2_transport_send(transport,
                                  (const uint8_t *)"server hello", 12, 101) == 12);
    RDPUDP2Packet response;
    assert(rdpudp2_decode(capture.datagrams[1], capture.datagram_lengths[1],
                          logical, &response));
    assert(response.data_sequence == 1);
    assert(response.channel_sequence == 1);
    rdpudp2_transport_free(transport);
}

static void test_udp2_ack_vector_gap_recovery(void) {
    Capture capture = {0};
    RDPUDP2Transport *receiver = rdpudp2_transport_new(
        1232, 1232, capture_send, capture_deliver, &capture);
    assert(receiver);

    uint8_t wire[RDPUDP2_MAX_DATAGRAM];
    size_t length = encode_data(1, 1, "one", wire);
    assert(rdpudp2_transport_receive(receiver, wire, length, 100));
    assert(rdpudp2_transport_tick(receiver, 125));
    assert(capture.datagram_count == 1);
    assert(capture.delivered_length == 3);

    length = encode_data(3, 3, "three", wire);
    assert(rdpudp2_transport_receive(receiver, wire, length, 200));
    assert(capture.datagram_count == 2);

    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet vector;
    assert(rdpudp2_decode(capture.datagrams[1], capture.datagram_lengths[1],
                          logical, &vector));
    assert((vector.flags & RDPUDP2_FLAG_ACKVEC) != 0);
    assert(vector.ack_vector.base_sequence == 2);
    assert(vector.ack_vector.encoded_size == 2);
    assert(vector.ack_vector.encoded[0] == 0x81); /* one missing */
    assert(vector.ack_vector.encoded[1] == 0xc1); /* one received */
    assert(vector.ack_vector.timestamp_present);
    assert(vector.ack_vector.timestamp == 200u * 250u);

    length = encode_data(2, 2, "two", wire);
    assert(rdpudp2_transport_receive(receiver, wire, length, 201));
    assert(capture.datagram_count == 3);
    assert(capture.delivered_length == 11);
    assert(memcmp(capture.delivered, "onetwothree", 11) == 0);
    RDPUDP2Stats stats;
    rdpudp2_transport_get_stats(receiver, &stats);
    assert(stats.acknowledgement_vectors_sent == 1);
    rdpudp2_transport_free(receiver);
}

static void test_udp2_cumulative_ack_and_congestion_window(void) {
    Capture capture = {0};
    RDPUDP2Transport *sender = rdpudp2_transport_new(
        64, 64, capture_send, capture_deliver, &capture);
    assert(sender);

    uint8_t payload[20u * 52u];
    memset(payload, 0x5a, sizeof(payload));
    size_t accepted = rdpudp2_transport_send(sender, payload, sizeof(payload), 100);
    assert(accepted == 10u * 52u);
    assert(capture.datagram_count == 10);

    RDPUDP2Stats stats;
    rdpudp2_transport_get_stats(sender, &stats);
    assert(stats.inflight_packets == 10);
    assert(stats.congestion_window_packets == 10.0);

    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet last;
    assert(rdpudp2_decode(capture.datagrams[9], capture.datagram_lengths[9],
                          logical, &last));
    RDPUDP2Packet ack = {0};
    ack.flags = RDPUDP2_FLAG_ACK;
    ack.log_window_size = 15;
    ack.ack.sequence = last.data_sequence;
    ack.ack.send_gap_ms = 20;
    uint8_t ack_wire[RDPUDP2_MAX_DATAGRAM];
    size_t ack_length = 0;
    assert(rdpudp2_encode(&ack, ack_wire, &ack_length));
    assert(rdpudp2_transport_receive(sender, ack_wire, ack_length, 200));
    rdpudp2_transport_get_stats(sender, &stats);
    assert(stats.inflight_packets == 0);
    assert(stats.smoothed_rtt_ms == 80);
    assert(stats.retransmit_timeout_ms == 300);
    assert(stats.congestion_window_packets == 20.0);

    accepted = rdpudp2_transport_send(sender, payload + accepted,
                                      sizeof(payload) - accepted, 201);
    assert(accepted == 10u * 52u);
    assert(capture.datagram_count == 20);
    rdpudp2_transport_free(sender);
}

static void test_udp2_fast_retransmit(void) {
    Capture capture = {0};
    RDPUDP2Transport *sender = rdpudp2_transport_new(
        64, 64, capture_send, capture_deliver, &capture);
    assert(sender);

    uint8_t payload[5u * 52u];
    memset(payload, 0xa5, sizeof(payload));
    assert(rdpudp2_transport_send(sender, payload, sizeof(payload), 100) ==
           sizeof(payload));
    assert(capture.datagram_count == 5);

    const uint8_t states = 0x0e; /* seq 1 missing, seq 2..4 received. */
    RDPUDP2Packet vector = {0};
    vector.flags = RDPUDP2_FLAG_ACKVEC;
    vector.log_window_size = 12;
    vector.ack_vector.base_sequence = 1;
    vector.ack_vector.encoded_size = 1;
    vector.ack_vector.encoded = &states;
    uint8_t wire[RDPUDP2_MAX_DATAGRAM];
    size_t wire_length = 0;
    assert(rdpudp2_encode(&vector, wire, &wire_length));
    assert(rdpudp2_transport_receive(sender, wire, wire_length, 125));
    assert(rdpudp2_transport_tick(sender, 125));
    assert(capture.datagram_count == 6);

    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet retransmit;
    assert(rdpudp2_decode(capture.datagrams[5], capture.datagram_lengths[5],
                          logical, &retransmit));
    assert((retransmit.flags & RDPUDP2_FLAG_DATA) != 0);
    assert((retransmit.flags & RDPUDP2_FLAG_AOA) != 0);
    assert(retransmit.channel_sequence == 1);
    assert(retransmit.data_sequence > 5);

    RDPUDP2Stats stats;
    rdpudp2_transport_get_stats(sender, &stats);
    assert(stats.fast_retransmissions == 1);
    assert(stats.timeout_retransmissions == 0);
    assert(stats.loss_events == 1);
    assert(stats.inflight_packets == 2);
    assert(stats.congestion_window_packets == 6.5);
    rdpudp2_transport_free(sender);
}

typedef struct {
    uint8_t datagrams[128][RDPUDP2_MAX_DATAGRAM];
    size_t lengths[128];
    size_t count;
} DatagramQueue;

typedef struct {
    DatagramQueue *outgoing;
    uint8_t delivered[8192];
    size_t delivered_length;
} SimEndpoint;

static bool simulated_send(void *context, const uint8_t *data, size_t length) {
    SimEndpoint *endpoint = context;
    DatagramQueue *queue = endpoint->outgoing;
    assert(queue->count < 128);
    assert(length <= RDPUDP2_MAX_DATAGRAM);
    memcpy(queue->datagrams[queue->count], data, length);
    queue->lengths[queue->count] = length;
    queue->count++;
    return true;
}

static void simulated_deliver(void *context, const uint8_t *data, size_t length) {
    SimEndpoint *endpoint = context;
    assert(length <= sizeof(endpoint->delivered) - endpoint->delivered_length);
    memcpy(endpoint->delivered + endpoint->delivered_length, data, length);
    endpoint->delivered_length += length;
}

static void test_udp2_end_to_end_loss_and_reordering(void) {
    DatagramQueue a_to_b = {0};
    DatagramQueue b_to_a = {0};
    SimEndpoint a = { .outgoing = &a_to_b };
    SimEndpoint b = { .outgoing = &b_to_a };
    RDPUDP2Transport *sender = rdpudp2_transport_new(
        64, 64, simulated_send, simulated_deliver, &a);
    RDPUDP2Transport *receiver = rdpudp2_transport_new(
        64, 64, simulated_send, simulated_deliver, &b);
    assert(sender && receiver);

    uint8_t payload[5u * 52u];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i * 37u + 11u);
    assert(rdpudp2_transport_send(sender, payload, sizeof(payload), 100) ==
           sizeof(payload));
    assert(a_to_b.count == 5);

    /* Drop packet 2 and deliver the remaining datagrams with a gap. */
    const size_t delivery_order[] = { 0, 2, 3, 4 };
    for (size_t i = 0; i < sizeof(delivery_order) / sizeof(delivery_order[0]); ++i) {
        size_t index = delivery_order[i];
        assert(rdpudp2_transport_receive(receiver, a_to_b.datagrams[index],
                                         a_to_b.lengths[index], 101u + i));
    }
    assert(b.delivered_length == 52);
    assert(b_to_a.count >= 4);

    for (size_t i = 0; i < b_to_a.count; ++i) {
        assert(rdpudp2_transport_receive(sender, b_to_a.datagrams[i],
                                         b_to_a.lengths[i], 110u + i));
    }
    assert(rdpudp2_transport_tick(sender, 120));
    assert(a_to_b.count == 6); /* Fast retransmission of channel packet 2. */

    assert(rdpudp2_transport_receive(receiver, a_to_b.datagrams[5],
                                     a_to_b.lengths[5], 121));
    assert(b.delivered_length == sizeof(payload));
    assert(memcmp(b.delivered, payload, sizeof(payload)) == 0);

    size_t acknowledgements_before_tick = b_to_a.count;
    assert(rdpudp2_transport_tick(receiver, 146));
    assert(b_to_a.count == acknowledgements_before_tick + 1u);
    assert(rdpudp2_transport_receive(
        sender, b_to_a.datagrams[acknowledgements_before_tick],
        b_to_a.lengths[acknowledgements_before_tick], 150));

    RDPUDP2Stats sender_stats;
    RDPUDP2Stats receiver_stats;
    rdpudp2_transport_get_stats(sender, &sender_stats);
    rdpudp2_transport_get_stats(receiver, &receiver_stats);
    assert(sender_stats.inflight_packets == 0);
    assert(sender_stats.fast_retransmissions == 1);
    assert(sender_stats.timeout_retransmissions == 0);
    assert(receiver_stats.out_of_order_data == 3);
    assert(receiver_stats.stream_bytes_delivered == sizeof(payload));

    rdpudp2_transport_free(receiver);
    rdpudp2_transport_free(sender);
}

static void test_udp2_sequence_space_starts_at_one(void) {
    DatagramQueue a_to_b = {0};
    DatagramQueue b_to_a = {0};
    SimEndpoint a = { .outgoing = &a_to_b };
    SimEndpoint b = { .outgoing = &b_to_a };
    RDPUDP2Transport *sender = rdpudp2_transport_new(
        64, 64, simulated_send, simulated_deliver, &a);
    RDPUDP2Transport *receiver = rdpudp2_transport_new(
        64, 64, simulated_send, simulated_deliver, &b);
    assert(sender && receiver);

    uint8_t payload[104];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)i;
    assert(rdpudp2_transport_send(sender, payload, sizeof(payload), 100) ==
           sizeof(payload));
    assert(a_to_b.count == 2);

    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet first, second;
    assert(rdpudp2_decode(a_to_b.datagrams[0], a_to_b.lengths[0], logical, &first));
    assert(first.data_sequence == 1u);
    assert(first.channel_sequence == 1u);
    assert(rdpudp2_transport_receive(receiver, a_to_b.datagrams[0],
                                     a_to_b.lengths[0], 101));
    assert(rdpudp2_decode(a_to_b.datagrams[1], a_to_b.lengths[1], logical, &second));
    assert(second.data_sequence == 2u);
    assert(second.channel_sequence == 2u);
    assert(rdpudp2_transport_receive(receiver, a_to_b.datagrams[1],
                                     a_to_b.lengths[1], 102));
    assert(b.delivered_length == sizeof(payload));
    assert(memcmp(b.delivered, payload, sizeof(payload)) == 0);

    assert(rdpudp2_transport_tick(receiver, 127));
    assert(b_to_a.count == 1);
    RDPUDP2Packet ack;
    assert(rdpudp2_decode(b_to_a.datagrams[0], b_to_a.lengths[0], logical, &ack));
    assert((ack.flags & RDPUDP2_FLAG_ACK) != 0);
    assert(ack.ack.sequence == 2u);
    assert(rdpudp2_transport_receive(sender, b_to_a.datagrams[0],
                                     b_to_a.lengths[0], 130));
    RDPUDP2Stats stats;
    rdpudp2_transport_get_stats(sender, &stats);
    assert(stats.inflight_packets == 0);

    uint8_t invalid_wire[RDPUDP2_MAX_DATAGRAM];
    size_t invalid_length = encode_data(1u, 0u, "invalid", invalid_wire);
    assert(!rdpudp2_transport_receive(receiver, invalid_wire, invalid_length,
                                      131));

    rdpudp2_transport_free(receiver);
    rdpudp2_transport_free(sender);
}

static void test_udp2_ack_of_acks_uses_actual_sender_floor(void) {
    Capture capture = {0};
    RDPUDP2Transport *sender = rdpudp2_transport_new(
        64, 64, capture_send, capture_deliver, &capture);
    assert(sender);
    uint8_t payload[20u * 52u];
    memset(payload, 0x3c, sizeof(payload));

    assert(rdpudp2_transport_send(sender, payload, 10u * 52u, 100) ==
           10u * 52u);
    RDPUDP2Packet ack = {0};
    ack.flags = RDPUDP2_FLAG_ACK;
    ack.log_window_size = 12;
    ack.ack.sequence = 10;
    uint8_t wire[RDPUDP2_MAX_DATAGRAM];
    size_t wire_length = 0;
    assert(rdpudp2_encode(&ack, wire, &wire_length));
    assert(rdpudp2_transport_receive(sender, wire, wire_length, 120));
    assert(rdpudp2_transport_send(sender, payload, sizeof(payload), 121) ==
           sizeof(payload));
    assert(capture.datagram_count == 30);

    const uint8_t states[] = { 0x81, 0xd3 }; /* seq 11 missing, 12..30 received */
    RDPUDP2Packet vector = {0};
    vector.flags = RDPUDP2_FLAG_ACKVEC;
    vector.log_window_size = 12;
    vector.ack_vector.base_sequence = 11;
    vector.ack_vector.encoded_size = sizeof(states);
    vector.ack_vector.encoded = states;
    assert(rdpudp2_encode(&vector, wire, &wire_length));
    assert(rdpudp2_transport_receive(sender, wire, wire_length, 140));
    assert(rdpudp2_transport_tick(sender, 140));
    assert(capture.datagram_count == 31);

    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet retransmit;
    assert(rdpudp2_decode(capture.datagrams[30], capture.datagram_lengths[30],
                          logical, &retransmit));
    assert(retransmit.data_sequence == 31);
    assert((retransmit.flags & RDPUDP2_FLAG_AOA) != 0);
    assert(retransmit.ack_of_acks_sequence == 31);
    rdpudp2_transport_free(sender);
}

static void test_udp2_ack_and_retransmit(void) {
    Capture capture = {0};
    RDPUDP2Transport *sender = rdpudp2_transport_new(
        1232, 1232, capture_send, capture_deliver, &capture);
    assert(sender);
    assert(rdpudp2_transport_send(sender, (const uint8_t *)"payload", 7, 100) == 7);
    assert(capture.datagram_count == 1);

    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet sent;
    assert(rdpudp2_decode(capture.datagrams[0], capture.datagram_lengths[0],
                          logical, &sent));
    uint16_t original_data_sequence = sent.data_sequence;
    uint16_t original_channel_sequence = sent.channel_sequence;

    assert(rdpudp2_transport_tick(sender, 399));
    assert(capture.datagram_count == 1);
    assert(rdpudp2_transport_tick(sender, 400));
    assert(capture.datagram_count == 2);
    assert(rdpudp2_decode(capture.datagrams[1], capture.datagram_lengths[1],
                          logical, &sent));
    assert(sent.data_sequence != original_data_sequence);
    assert(sent.channel_sequence == original_channel_sequence);

    RDPUDP2Packet ack = {0};
    ack.flags = RDPUDP2_FLAG_ACK;
    ack.log_window_size = 12;
    ack.ack.sequence = sent.data_sequence;
    uint8_t ack_wire[RDPUDP2_MAX_DATAGRAM];
    size_t ack_length = 0;
    assert(rdpudp2_encode(&ack, ack_wire, &ack_length));
    assert(rdpudp2_transport_receive(sender, ack_wire, ack_length, 410));
    RDPUDP2Stats stats;
    rdpudp2_transport_get_stats(sender, &stats);
    assert(stats.inflight_packets == 0);
    assert(stats.datagrams_retransmitted == 1);
    assert(stats.timeout_retransmissions == 1);
    assert(stats.loss_events == 1);
    assert(rdpudp2_transport_tick(sender, 700));
    assert(capture.datagram_count == 2);
    rdpudp2_transport_free(sender);
}

typedef struct {
    unsigned count;
    uint8_t actions[4];
    uint16_t lengths[4];
} FrameCapture;

static bool capture_frame(void *context, const RDPEMTFrame *frame) {
    FrameCapture *capture = context;
    assert(capture->count < 4);
    capture->actions[capture->count] = frame->action;
    capture->lengths[capture->count] = frame->payload_length;
    capture->count++;
    return true;
}

static bool reject_frame(void *context, const RDPEMTFrame *frame) {
    (void)context;
    (void)frame;
    return false;
}

static void test_rdpemt(void) {
    uint8_t cookie[RDPEMT_SECURITY_COOKIE_LENGTH];
    for (size_t i = 0; i < sizeof(cookie); i++) cookie[i] = (uint8_t)i;
    uint8_t request[28] = {0};
    request[0] = RDPEMT_ACTION_CREATE_REQUEST;
    request[1] = 24;
    request[3] = 4;
    request[4] = 0x78;
    request[5] = 0x56;
    request[6] = 0x34;
    request[7] = 0x12;
    memcpy(request + 12, cookie, sizeof(cookie));

    RDPEMTFrame frame;
    size_t consumed = 99;
    assert(rdpemt_parse_frame(request, 3, &frame, &consumed));
    assert(consumed == 0);
    assert(rdpemt_parse_frame(request, sizeof(request), &frame, &consumed));
    assert(consumed == sizeof(request));
    assert(rdpemt_validate_create_request(&frame, 0x12345678, cookie));
    cookie[0] ^= 1;
    assert(!rdpemt_validate_create_request(&frame, 0x12345678, cookie));

    uint8_t response[8];
    size_t response_length = 0;
    assert(rdpemt_encode_create_response(0, response, &response_length));
    assert(response_length == 8);

    uint8_t data_frame[32];
    size_t data_frame_length = 0;
    assert(rdpemt_encode_data((const uint8_t *)"abc", 3, data_frame,
                              sizeof(data_frame), &data_frame_length));

    uint8_t stream[64];
    memcpy(stream, response, response_length);
    memcpy(stream + response_length, data_frame, data_frame_length);
    size_t stream_length = response_length + data_frame_length;
    FrameCapture frames = {0};
    RDPEMTDecoder *decoder = rdpemt_decoder_new(capture_frame, &frames);
    assert(decoder);
    assert(rdpemt_decoder_feed(decoder, stream, 5));
    assert(frames.count == 0);
    assert(rdpemt_decoder_feed(decoder, stream + 5, stream_length - 5));
    assert(frames.count == 2);
    assert(frames.actions[0] == RDPEMT_ACTION_CREATE_RESPONSE);
    assert(frames.actions[1] == RDPEMT_ACTION_DATA);
    assert(frames.lengths[1] == 3);
    rdpemt_decoder_free(decoder);

    uint8_t malformed_subheader[] = {
        RDPEMT_ACTION_DATA, 0, 0, 6, 1, 0
    };
    consumed = 0;
    assert(!rdpemt_parse_frame(malformed_subheader,
                               sizeof(malformed_subheader), &frame, &consumed));

    uint8_t valid_control[] = {
        RDPEMT_ACTION_DATA, 0, 0, 10,
        6, 0, 1, 0, 0x14, 0x00
    };
    consumed = 0;
    assert(rdpemt_parse_frame(valid_control, sizeof(valid_control),
                              &frame, &consumed));
    assert(consumed == sizeof(valid_control));
    assert(frame.payload_length == 0);
    assert(frame.subheaders_length == 6);

    uint8_t unknown_subheader[] = {
        RDPEMT_ACTION_DATA, 0, 0, 6, 2, 2
    };
    consumed = 0;
    assert(!rdpemt_parse_frame(unknown_subheader,
                               sizeof(unknown_subheader), &frame, &consumed));

    RDPEMTDecoder *rejecting = rdpemt_decoder_new(reject_frame, NULL);
    assert(rejecting);
    assert(!rdpemt_decoder_feed(rejecting, data_frame, data_frame_length));
    rdpemt_decoder_free(rejecting);
}

int main(void) {
    test_udp_bootstrap();
    test_udp2_codec();
    test_udp2_reordering();
    test_udp2_mstsc_initial_packet_compatibility();
    test_udp2_ack_vector_gap_recovery();
    test_udp2_cumulative_ack_and_congestion_window();
    test_udp2_fast_retransmit();
    test_udp2_end_to_end_loss_and_reordering();
    test_udp2_sequence_space_starts_at_one();
    test_udp2_ack_of_acks_uses_actual_sender_floor();
    test_udp2_ack_and_retransmit();
    test_rdpemt();
    puts("RDP UDP protocol tests passed");
    return 0;
}
