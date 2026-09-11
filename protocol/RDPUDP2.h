#ifndef MACOS_RDP_UDP2_H
#define MACOS_RDP_UDP2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RDPUDP2_MAX_DATAGRAM 1232u
#define RDPUDP2_MAX_LOG_WINDOW 15u
#define RDPUDP2_LOCAL_LOG_WINDOW 12u

enum {
    RDPUDP2_FLAG_ACK = 0x001,
    RDPUDP2_FLAG_DATA = 0x004,
    RDPUDP2_FLAG_ACKVEC = 0x008,
    RDPUDP2_FLAG_AOA = 0x010,
    RDPUDP2_FLAG_OVERHEAD_SIZE = 0x040,
    RDPUDP2_FLAG_DELAY_ACK_INFO = 0x100,
};

typedef struct {
    uint16_t sequence;
    uint32_t received_timestamp;
    uint8_t send_gap_ms;
    uint8_t delayed_count;
    uint8_t delayed_scale;
    const uint8_t *delayed_additions;
} RDPUDP2Ack;

typedef struct {
    uint16_t base_sequence;
    bool timestamp_present;
    uint32_t timestamp;
    uint8_t send_gap_ms;
    uint8_t encoded_size;
    const uint8_t *encoded;
} RDPUDP2AckVector;

typedef struct {
    uint16_t flags;
    uint8_t log_window_size;
    bool dummy;

    RDPUDP2Ack ack;
    uint8_t overhead_size;
    uint8_t max_delayed_acks;
    uint16_t delayed_ack_timeout_ms;
    uint16_t ack_of_acks_sequence;
    uint16_t data_sequence;
    uint16_t channel_sequence;
    RDPUDP2AckVector ack_vector;

    const uint8_t *data;
    size_t data_length;
} RDPUDP2Packet;

/* The decoder restores the byte displaced by PacketPrefixByte into logical.
 * Packet data pointers returned in out_packet refer to logical. */
bool rdpudp2_decode(const uint8_t *wire, size_t wire_length,
                    uint8_t logical[RDPUDP2_MAX_DATAGRAM],
                    RDPUDP2Packet *out_packet);

bool rdpudp2_encode(const RDPUDP2Packet *packet,
                    uint8_t wire[RDPUDP2_MAX_DATAGRAM],
                    size_t *wire_length);

typedef bool (*RDPUDP2SendDatagram)(void *context, const uint8_t *data,
                                    size_t length);
typedef void (*RDPUDP2DeliverStream)(void *context, const uint8_t *data,
                                    size_t length);

typedef struct RDPUDP2Transport RDPUDP2Transport;

typedef struct {
    uint64_t datagrams_sent;
    uint64_t datagrams_received;
    uint64_t datagrams_retransmitted;
    uint64_t fast_retransmissions;
    uint64_t timeout_retransmissions;
    uint64_t loss_events;
    uint64_t acknowledgements_sent;
    uint64_t delayed_acknowledgements_sent;
    uint64_t acknowledgements_received;
    uint64_t acknowledgement_vectors_sent;
    uint64_t acknowledgement_vectors_received;
    uint64_t stream_bytes_accepted;
    uint64_t stream_bytes_delivered;
    uint64_t out_of_order_data;
    uint64_t duplicate_data;
    uint64_t malformed_datagrams;
    size_t inflight_packets;
    size_t peak_inflight_packets;
    uint32_t smoothed_rtt_ms;
    uint32_t retransmit_timeout_ms;
    double congestion_window_packets;
    bool connection_timed_out;
} RDPUDP2Stats;

RDPUDP2Transport *rdpudp2_transport_new(uint16_t send_mtu,
                                        uint16_t receive_mtu,
                                        RDPUDP2SendDatagram send_datagram,
                                        RDPUDP2DeliverStream deliver_stream,
                                        void *context);
void rdpudp2_transport_free(RDPUDP2Transport *transport);

/* Returns the number of stream bytes accepted into the reliable window. */
size_t rdpudp2_transport_send(RDPUDP2Transport *transport,
                              const uint8_t *data, size_t length,
                              uint64_t now_ms);

bool rdpudp2_transport_receive(RDPUDP2Transport *transport,
                               const uint8_t *datagram, size_t length,
                               uint64_t now_ms);

/* Runs retransmit, keepalive and dead-peer timers. */
bool rdpudp2_transport_tick(RDPUDP2Transport *transport, uint64_t now_ms);

void rdpudp2_transport_get_stats(const RDPUDP2Transport *transport,
                                 RDPUDP2Stats *stats);

#ifdef __cplusplus
}
#endif

#endif
