#include "protocol/RDPUDP2.h"

#include <stdlib.h>
#include <string.h>

#define RDPUDP2_WINDOW_SIZE (1u << RDPUDP2_LOCAL_LOG_WINDOW)
#define RDPUDP2_DATA_MAP_SIZE 65536u
#define RDPUDP2_MIN_RETRANSMIT_MS 300u
#define RDPUDP2_MAX_RETRANSMIT_MS 120000u
#define RDPUDP2_MAX_RETRANSMISSIONS 5u
#define RDPUDP2_KEEPALIVE_MS 4000u
#define RDPUDP2_LOST_CONNECTION_MS 16000u
#define RDPUDP2_DEFAULT_DELAY_ACKS 8u
#define RDPUDP2_DEFAULT_DELAY_ACK_MS 25u
#define RDPUDP2_MAX_DELAY_ACK_MS 200u
#define RDPUDP2_INITIAL_CWND 10.0
#define RDPUDP2_MIN_CWND 2.0
#define RDPUDP2_FAST_RETRANSMIT_THRESHOLD 3u
#define RDPUDP2_KNOWN_FLAGS (RDPUDP2_FLAG_ACK | RDPUDP2_FLAG_DATA | \
                             RDPUDP2_FLAG_ACKVEC | RDPUDP2_FLAG_AOA | \
                             RDPUDP2_FLAG_OVERHEAD_SIZE | \
                             RDPUDP2_FLAG_DELAY_ACK_INFO)
/* Windows build 26200 sets bit 0x200 on its first RDP-UDP2 DATA packets even
 * though the public MS-RDPEUDP2 flag table still leaves that bit reserved.
 * The following known payloads retain their documented offsets, so tolerate
 * the bit while decoding without assigning it a meaning or emitting it. */
#define RDPUDP2_DECODE_COMPAT_FLAGS 0x200u

typedef struct {
    bool used;
    uint16_t data_sequence;
    uint16_t channel_sequence;
    uint64_t sent_at_ms;
    uint32_t retransmissions;
    size_t payload_length;
    uint8_t payload[RDPUDP2_MAX_DATAGRAM];
} RDPUDP2TxSlot;

typedef struct {
    bool used;
    uint16_t channel_sequence;
    size_t payload_length;
    uint8_t payload[RDPUDP2_MAX_DATAGRAM];
} RDPUDP2RxSlot;

typedef struct {
    bool valid;
    bool received;
    uint16_t data_sequence;
    uint64_t received_at_ms;
} RDPUDP2AckRxSlot;

struct RDPUDP2Transport {
    uint16_t send_mtu;
    uint16_t receive_mtu;
    uint8_t local_log_window;
    uint8_t peer_log_window;
    uint16_t next_data_sequence;
    uint16_t next_channel_sequence;
    uint16_t next_receive_channel_sequence;
    uint64_t last_sent_ms;
    uint64_t last_received_ms;
    bool have_received;

    uint32_t smoothed_rtt_ms;
    uint32_t rtt_variation_ms;
    uint32_t retransmit_timeout_ms;
    bool have_rtt;
    double congestion_window;
    double slow_start_threshold;
    uint64_t last_congestion_event_ms;

    RDPUDP2AckRxSlot *ack_rx;
    bool ack_window_active;
    uint16_t ack_base_sequence;
    uint16_t ack_highest_sequence;
    size_t pending_ack_count;
    uint64_t first_unacknowledged_ms;
    bool have_last_cumulative_ack;
    uint16_t last_cumulative_ack;
    uint64_t last_cumulative_receive_ms;
    bool ack_floor_valid;
    uint16_t ack_floor_sequence;
    uint8_t peer_max_delayed_acks;
    uint16_t peer_delayed_ack_timeout_ms;
    uint8_t delay_ack_advertisements_remaining;

    bool ack_of_acks_pending;
    uint16_t ack_of_acks_sequence;
    uint64_t last_ack_of_acks_sent_ms;
    bool fast_loss_pending;
    uint16_t fast_loss_sequence;

    RDPUDP2SendDatagram send_datagram;
    RDPUDP2DeliverStream deliver_stream;
    void *context;

    RDPUDP2TxSlot *tx;
    RDPUDP2RxSlot *rx;
    int32_t *data_sequence_to_slot;
    size_t inflight;
    RDPUDP2Stats stats;
};

static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le24(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static void write_le16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void write_le24(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
}

static bool take(size_t *cursor, size_t count, size_t length) {
    if (*cursor > length || count > length - *cursor) return false;
    *cursor += count;
    return true;
}

bool rdpudp2_decode(const uint8_t *wire, size_t wire_length,
                    uint8_t logical[RDPUDP2_MAX_DATAGRAM],
                    RDPUDP2Packet *out_packet) {
    if (!wire || !logical || !out_packet || wire_length < 8 ||
        wire_length > RDPUDP2_MAX_DATAGRAM)
        return false;

    memcpy(logical, wire, wire_length);
    uint8_t prefix = wire[7];
    logical[7] = wire[0];

    memset(out_packet, 0, sizeof(*out_packet));
    uint8_t packet_type = (prefix >> 1) & 0x0f;
    if ((prefix & 0x01) != 0 || (packet_type != 0 && packet_type != 8))
        return false;
    out_packet->dummy = packet_type == 8;
    uint8_t short_length = prefix >> 5;
    size_t logical_length = short_length < 7 ? (size_t)short_length + 1u
                                             : wire_length;
    if (logical_length < 3 || logical_length > wire_length) return false;

    size_t cursor = 1;
    if (!take(&cursor, 2, logical_length)) return false;
    uint16_t header = read_le16(logical + 1);
    out_packet->flags = header & 0x0fff;
    out_packet->log_window_size = (uint8_t)(header >> 12);
    if (out_packet->log_window_size > RDPUDP2_MAX_LOG_WINDOW ||
        out_packet->flags == 0 ||
        (out_packet->flags &
         ~(RDPUDP2_KNOWN_FLAGS | RDPUDP2_DECODE_COMPAT_FLAGS)) != 0)
        return false;
    if ((out_packet->flags & RDPUDP2_FLAG_ACK) &&
        (out_packet->flags & RDPUDP2_FLAG_ACKVEC))
        return false;

    if (out_packet->flags & RDPUDP2_FLAG_ACK) {
        size_t start = cursor;
        if (!take(&cursor, 7, logical_length)) return false;
        out_packet->ack.sequence = read_le16(logical + start);
        out_packet->ack.received_timestamp = read_le24(logical + start + 2);
        out_packet->ack.send_gap_ms = logical[start + 5];
        out_packet->ack.delayed_count = logical[start + 6] & 0x0f;
        out_packet->ack.delayed_scale = logical[start + 6] >> 4;
        if (!take(&cursor, out_packet->ack.delayed_count, logical_length)) return false;
        out_packet->ack.delayed_additions = logical + start + 7;
    }
    if (out_packet->flags & RDPUDP2_FLAG_OVERHEAD_SIZE) {
        if (!take(&cursor, 1, logical_length)) return false;
        out_packet->overhead_size = logical[cursor - 1];
    }
    if (out_packet->flags & RDPUDP2_FLAG_DELAY_ACK_INFO) {
        size_t start = cursor;
        if (!take(&cursor, 3, logical_length)) return false;
        out_packet->max_delayed_acks = logical[start];
        out_packet->delayed_ack_timeout_ms = read_le16(logical + start + 1);
    }
    if (out_packet->flags & RDPUDP2_FLAG_AOA) {
        if (!take(&cursor, 2, logical_length)) return false;
        out_packet->ack_of_acks_sequence = read_le16(logical + cursor - 2);
    }
    if (out_packet->flags & RDPUDP2_FLAG_DATA) {
        if (!take(&cursor, 2, logical_length)) return false;
        out_packet->data_sequence = read_le16(logical + cursor - 2);
    }
    if (out_packet->flags & RDPUDP2_FLAG_ACKVEC) {
        size_t start = cursor;
        if (!take(&cursor, 3, logical_length)) return false;
        out_packet->ack_vector.base_sequence = read_le16(logical + start);
        out_packet->ack_vector.encoded_size = logical[start + 2] & 0x7f;
        out_packet->ack_vector.timestamp_present = (logical[start + 2] & 0x80) != 0;
        if (out_packet->ack_vector.timestamp_present) {
            if (!take(&cursor, 4, logical_length)) return false;
            out_packet->ack_vector.timestamp = read_le24(logical + start + 3);
            out_packet->ack_vector.send_gap_ms = logical[start + 6];
        }
        if (!take(&cursor, out_packet->ack_vector.encoded_size, logical_length))
            return false;
        out_packet->ack_vector.encoded = logical + cursor - out_packet->ack_vector.encoded_size;
    }
    if (out_packet->flags & RDPUDP2_FLAG_DATA) {
        if (!take(&cursor, 2, logical_length)) return false;
        out_packet->channel_sequence = read_le16(logical + cursor - 2);
        out_packet->data = logical + cursor;
        out_packet->data_length = logical_length - cursor;
    } else {
        /* The mandatory 8-byte wire minimum is padding, not payload. */
        out_packet->data = NULL;
        out_packet->data_length = 0;
    }
    return true;
}

static bool append(uint8_t *logical, size_t *cursor, const void *source,
                   size_t count) {
    if (*cursor > RDPUDP2_MAX_DATAGRAM ||
        count > RDPUDP2_MAX_DATAGRAM - *cursor)
        return false;
    if (count) memcpy(logical + *cursor, source, count);
    *cursor += count;
    return true;
}

bool rdpudp2_encode(const RDPUDP2Packet *packet,
                    uint8_t wire[RDPUDP2_MAX_DATAGRAM],
                    size_t *wire_length) {
    if (!packet || !wire || !wire_length || packet->flags == 0 ||
        (packet->flags & ~RDPUDP2_KNOWN_FLAGS) != 0 ||
        packet->log_window_size > RDPUDP2_MAX_LOG_WINDOW ||
        ((packet->flags & RDPUDP2_FLAG_ACK) &&
         (packet->flags & RDPUDP2_FLAG_ACKVEC)))
        return false;

    uint8_t logical[RDPUDP2_MAX_DATAGRAM] = {0};
    size_t cursor = 1;
    uint16_t header = (packet->flags & 0x0fff) |
                      ((uint16_t)packet->log_window_size << 12);
    write_le16(logical + cursor, header);
    cursor += 2;

    if (packet->flags & RDPUDP2_FLAG_ACK) {
        if (packet->ack.delayed_count > 15 ||
            (packet->ack.delayed_count && !packet->ack.delayed_additions))
            return false;
        uint8_t fixed[7];
        write_le16(fixed, packet->ack.sequence);
        write_le24(fixed + 2, packet->ack.received_timestamp);
        fixed[5] = packet->ack.send_gap_ms;
        fixed[6] = (uint8_t)((packet->ack.delayed_scale << 4) |
                             packet->ack.delayed_count);
        if (!append(logical, &cursor, fixed, sizeof(fixed)) ||
            !append(logical, &cursor, packet->ack.delayed_additions,
                    packet->ack.delayed_count))
            return false;
    }
    if (packet->flags & RDPUDP2_FLAG_OVERHEAD_SIZE) {
        if (!append(logical, &cursor, &packet->overhead_size, 1)) return false;
    }
    if (packet->flags & RDPUDP2_FLAG_DELAY_ACK_INFO) {
        uint8_t value[3] = { packet->max_delayed_acks, 0, 0 };
        write_le16(value + 1, packet->delayed_ack_timeout_ms);
        if (!append(logical, &cursor, value, sizeof(value))) return false;
    }
    if (packet->flags & RDPUDP2_FLAG_AOA) {
        uint8_t value[2];
        write_le16(value, packet->ack_of_acks_sequence);
        if (!append(logical, &cursor, value, sizeof(value))) return false;
    }
    if (packet->flags & RDPUDP2_FLAG_DATA) {
        uint8_t value[2];
        write_le16(value, packet->data_sequence);
        if (!append(logical, &cursor, value, sizeof(value))) return false;
    }
    if (packet->flags & RDPUDP2_FLAG_ACKVEC) {
        if (packet->ack_vector.encoded_size > 127 ||
            (packet->ack_vector.encoded_size && !packet->ack_vector.encoded))
            return false;
        uint8_t fixed[7];
        size_t fixed_length = 3;
        write_le16(fixed, packet->ack_vector.base_sequence);
        fixed[2] = packet->ack_vector.encoded_size |
                   (packet->ack_vector.timestamp_present ? 0x80 : 0);
        if (packet->ack_vector.timestamp_present) {
            write_le24(fixed + 3, packet->ack_vector.timestamp);
            fixed[6] = packet->ack_vector.send_gap_ms;
            fixed_length = 7;
        }
        if (!append(logical, &cursor, fixed, fixed_length) ||
            !append(logical, &cursor, packet->ack_vector.encoded,
                    packet->ack_vector.encoded_size))
            return false;
    }
    if (packet->flags & RDPUDP2_FLAG_DATA) {
        if (packet->data_length && !packet->data) return false;
        uint8_t sequence[2];
        write_le16(sequence, packet->channel_sequence);
        if (!append(logical, &cursor, sequence, sizeof(sequence)) ||
            !append(logical, &cursor, packet->data, packet->data_length))
            return false;
    }

    size_t content_length = cursor - 1;
    uint8_t short_length = (uint8_t)(content_length < 7 ? content_length : 7);
    while (cursor < 8) logical[cursor++] = 0;
    uint8_t prefix = (uint8_t)((packet->dummy ? 8 : 0) << 1) |
                     (uint8_t)(short_length << 5);
    memcpy(wire, logical, cursor);
    wire[0] = logical[7];
    wire[7] = prefix;
    *wire_length = cursor;
    return true;
}

static int16_t sequence_delta(uint16_t value, uint16_t reference) {
    return (int16_t)(value - reference);
}

/* Windows skips zero for ChannelSeqNum even when the 16-bit wire value wraps.
 * DataSeqNum still uses the complete 16-bit space. */
static uint16_t channel_sequence_after(uint16_t sequence) {
    uint16_t next = (uint16_t)(sequence + 1u);
    return next == 0 ? 1u : next;
}

static uint8_t bounded_peer_log(uint8_t log_window) {
    return log_window > RDPUDP2_LOCAL_LOG_WINDOW
               ? RDPUDP2_LOCAL_LOG_WINDOW
               : log_window;
}

static uint32_t timestamp_4us(uint64_t time_ms) {
    return (uint32_t)((time_ms * 250u) & 0x00ffffffu);
}

static uint8_t saturating_gap_ms(uint64_t now_ms, uint64_t received_at_ms) {
    uint64_t gap = now_ms >= received_at_ms ? now_ms - received_at_ms : 0;
    return (uint8_t)(gap > 255u ? 255u : gap);
}

static void add_sender_controls(RDPUDP2Transport *t, RDPUDP2Packet *packet) {
    if (t->delay_ack_advertisements_remaining) {
        packet->flags |= RDPUDP2_FLAG_DELAY_ACK_INFO;
        packet->max_delayed_acks = RDPUDP2_DEFAULT_DELAY_ACKS;
        packet->delayed_ack_timeout_ms = RDPUDP2_DEFAULT_DELAY_ACK_MS;
    }
    if (t->ack_of_acks_pending) {
        packet->flags |= RDPUDP2_FLAG_AOA;
        packet->ack_of_acks_sequence = t->ack_of_acks_sequence;
    }
}

static void note_sender_controls_sent(RDPUDP2Transport *t,
                                      const RDPUDP2Packet *packet,
                                      uint64_t now_ms) {
    if ((packet->flags & RDPUDP2_FLAG_DELAY_ACK_INFO) &&
        t->delay_ack_advertisements_remaining)
        t->delay_ack_advertisements_remaining--;
    if (packet->flags & RDPUDP2_FLAG_AOA)
        t->last_ack_of_acks_sent_ms = now_ms;
}

static bool send_wire(RDPUDP2Transport *t, const uint8_t *wire, size_t length,
                      uint64_t now_ms, bool retransmit) {
    if (length > t->send_mtu || !t->send_datagram(t->context, wire, length))
        return false;
    t->last_sent_ms = now_ms;
    t->stats.datagrams_sent++;
    if (retransmit) t->stats.datagrams_retransmitted++;
    return true;
}

static bool encode_tx_slot(RDPUDP2Transport *t, RDPUDP2TxSlot *slot,
                           uint8_t wire[RDPUDP2_MAX_DATAGRAM], size_t *length,
                           RDPUDP2Packet *encoded_packet) {
    RDPUDP2Packet packet = {0};
    packet.flags = RDPUDP2_FLAG_DATA;
    packet.log_window_size = t->local_log_window;
    packet.data_sequence = slot->data_sequence;
    packet.channel_sequence = slot->channel_sequence;
    packet.data = slot->payload;
    packet.data_length = slot->payload_length;
    add_sender_controls(t, &packet);
    if (!rdpudp2_encode(&packet, wire, length)) return false;
    if (encoded_packet) *encoded_packet = packet;
    return true;
}

RDPUDP2Transport *rdpudp2_transport_new(uint16_t send_mtu,
                                        uint16_t receive_mtu,
                                        RDPUDP2SendDatagram send_datagram,
                                        RDPUDP2DeliverStream deliver_stream,
                                        void *context) {
    if (!send_datagram || !deliver_stream) return NULL;
    if (send_mtu < 64) send_mtu = 64;
    if (send_mtu > RDPUDP2_MAX_DATAGRAM) send_mtu = RDPUDP2_MAX_DATAGRAM;
    if (receive_mtu < 64) receive_mtu = 64;
    if (receive_mtu > RDPUDP2_MAX_DATAGRAM)
        receive_mtu = RDPUDP2_MAX_DATAGRAM;

    RDPUDP2Transport *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->tx = calloc(RDPUDP2_WINDOW_SIZE, sizeof(*t->tx));
    t->rx = calloc(RDPUDP2_WINDOW_SIZE, sizeof(*t->rx));
    t->ack_rx = calloc(RDPUDP2_WINDOW_SIZE, sizeof(*t->ack_rx));
    t->data_sequence_to_slot = malloc(RDPUDP2_DATA_MAP_SIZE * sizeof(int32_t));
    if (!t->tx || !t->rx || !t->ack_rx || !t->data_sequence_to_slot) {
        rdpudp2_transport_free(t);
        return NULL;
    }
    for (size_t i = 0; i < RDPUDP2_DATA_MAP_SIZE; i++)
        t->data_sequence_to_slot[i] = -1;
    t->send_mtu = send_mtu;
    t->receive_mtu = receive_mtu;
    t->local_log_window = RDPUDP2_LOCAL_LOG_WINDOW;
    t->peer_log_window = RDPUDP2_LOCAL_LOG_WINDOW;
    /* RDP-UDP2 starts a new 16-bit DataSeqNum/ChannelSeqNum space.  The
     * random 32-bit sequence values exchanged by the legacy RDP-UDP SYN are
     * not carried into this protocol. */
    t->next_data_sequence = 1u;
    t->next_channel_sequence = 1u;
    t->next_receive_channel_sequence = 1u;
    /* The peer can consume an initial run of dummy datagrams before its first
     * upper-layer DATA packet. Let that first received DataSeqNum establish
     * the acknowledgement floor instead of inventing gaps before it. */
    t->ack_floor_valid = false;
    t->peer_max_delayed_acks = RDPUDP2_DEFAULT_DELAY_ACKS;
    t->peer_delayed_ack_timeout_ms = RDPUDP2_DEFAULT_DELAY_ACK_MS;
    t->delay_ack_advertisements_remaining = 3;
    t->retransmit_timeout_ms = RDPUDP2_MIN_RETRANSMIT_MS;
    t->congestion_window = RDPUDP2_INITIAL_CWND;
    t->slow_start_threshold = (double)RDPUDP2_WINDOW_SIZE;
    t->send_datagram = send_datagram;
    t->deliver_stream = deliver_stream;
    t->context = context;
    return t;
}

void rdpudp2_transport_free(RDPUDP2Transport *t) {
    if (!t) return;
    free(t->tx);
    free(t->rx);
    free(t->ack_rx);
    free(t->data_sequence_to_slot);
    free(t);
}

static size_t send_window_limit(const RDPUDP2Transport *t) {
    size_t peer_window = (size_t)1u << bounded_peer_log(t->peer_log_window);
    size_t congestion = (size_t)t->congestion_window;
    if (congestion < 1) congestion = 1;
    return congestion < peer_window ? congestion : peer_window;
}

static RDPUDP2TxSlot *allocate_tx(RDPUDP2Transport *t, size_t *slot_index) {
    if (t->inflight >= send_window_limit(t)) return NULL;
    for (size_t i = 0; i < RDPUDP2_WINDOW_SIZE; i++) {
        if (!t->tx[i].used) {
            *slot_index = i;
            return &t->tx[i];
        }
    }
    return NULL;
}

size_t rdpudp2_transport_send(RDPUDP2Transport *t,
                              const uint8_t *data, size_t length,
                              uint64_t now_ms) {
    if (!t || (!data && length)) return 0;
    size_t accepted = 0;
    /* Reserve room for DATA, DelayAckInfo and AckOfAcks so retransmission can
     * add either control payload without exceeding the negotiated MTU. */
    size_t maximum_payload = t->send_mtu > 12 ? t->send_mtu - 12 : 0;
    while (accepted < length && maximum_payload) {
        size_t index = 0;
        RDPUDP2TxSlot *slot = allocate_tx(t, &index);
        if (!slot) break;
        size_t count = length - accepted;
        if (count > maximum_payload) count = maximum_payload;
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        slot->data_sequence = t->next_data_sequence++;
        slot->channel_sequence = t->next_channel_sequence;
        t->next_channel_sequence =
            channel_sequence_after(t->next_channel_sequence);
        slot->sent_at_ms = now_ms;
        slot->payload_length = count;
        memcpy(slot->payload, data + accepted, count);

        uint8_t wire[RDPUDP2_MAX_DATAGRAM];
        size_t wire_length = 0;
        RDPUDP2Packet packet;
        if (!encode_tx_slot(t, slot, wire, &wire_length, &packet) ||
            !send_wire(t, wire, wire_length, now_ms, false)) {
            memset(slot, 0, sizeof(*slot));
            break;
        }
        note_sender_controls_sent(t, &packet, now_ms);
        t->data_sequence_to_slot[slot->data_sequence] = (int32_t)index;
        t->inflight++;
        accepted += count;
        t->stats.stream_bytes_accepted += count;
        if (t->inflight > t->stats.peak_inflight_packets)
            t->stats.peak_inflight_packets = t->inflight;
    }
    t->stats.inflight_packets = t->inflight;
    return accepted;
}

static void update_rtt(RDPUDP2Transport *t, uint64_t sent_at_ms,
                       uint64_t now_ms, uint32_t peer_ack_delay_ms) {
    if (now_ms < sent_at_ms) return;
    uint64_t elapsed = now_ms - sent_at_ms;
    if (peer_ack_delay_ms >= elapsed) return;
    uint32_t sample = (uint32_t)(elapsed - peer_ack_delay_ms);
    if (sample == 0) sample = 1;
    if (!t->have_rtt) {
        t->smoothed_rtt_ms = sample;
        t->rtt_variation_ms = sample / 2u;
        t->have_rtt = true;
    } else {
        uint32_t difference = t->smoothed_rtt_ms > sample
                                  ? t->smoothed_rtt_ms - sample
                                  : sample - t->smoothed_rtt_ms;
        t->rtt_variation_ms = (3u * t->rtt_variation_ms + difference) / 4u;
        t->smoothed_rtt_ms = (7u * t->smoothed_rtt_ms + sample) / 8u;
    }
    uint64_t rto = (uint64_t)t->smoothed_rtt_ms * 2u;
    if (rto < RDPUDP2_MIN_RETRANSMIT_MS) rto = RDPUDP2_MIN_RETRANSMIT_MS;
    if (rto > RDPUDP2_MAX_RETRANSMIT_MS) rto = RDPUDP2_MAX_RETRANSMIT_MS;
    t->retransmit_timeout_ms = (uint32_t)rto;
}

static void congestion_on_ack(RDPUDP2Transport *t, size_t acknowledged) {
    if (!acknowledged) return;
    if (t->congestion_window < t->slow_start_threshold) {
        t->congestion_window += (double)acknowledged;
    } else {
        t->congestion_window +=
            (double)acknowledged / (t->congestion_window > 1.0
                                         ? t->congestion_window : 1.0);
    }
    size_t peer_window = (size_t)1u << bounded_peer_log(t->peer_log_window);
    if (t->congestion_window > (double)peer_window)
        t->congestion_window = (double)peer_window;
}

static void congestion_on_loss(RDPUDP2Transport *t, uint64_t now_ms) {
    uint32_t guard = t->smoothed_rtt_ms ? t->smoothed_rtt_ms
                                        : RDPUDP2_MIN_RETRANSMIT_MS;
    if (t->last_congestion_event_ms &&
        now_ms - t->last_congestion_event_ms < guard)
        return;
    t->slow_start_threshold = t->congestion_window / 2.0;
    if (t->slow_start_threshold < RDPUDP2_MIN_CWND)
        t->slow_start_threshold = RDPUDP2_MIN_CWND;
    t->congestion_window = t->slow_start_threshold;
    t->last_congestion_event_ms = now_ms;
    t->stats.loss_events++;
}

static bool acknowledge_one(RDPUDP2Transport *t, uint16_t sequence,
                            uint64_t now_ms, uint32_t ack_delay_ms,
                            bool take_rtt_sample) {
    int32_t index = t->data_sequence_to_slot[sequence];
    if (index < 0 || (size_t)index >= RDPUDP2_WINDOW_SIZE) return false;
    RDPUDP2TxSlot *slot = &t->tx[index];
    if (!slot->used || slot->data_sequence != sequence) return false;
    if (take_rtt_sample && slot->retransmissions == 0)
        update_rtt(t, slot->sent_at_ms, now_ms, ack_delay_ms);
    t->data_sequence_to_slot[sequence] = -1;
    memset(slot, 0, sizeof(*slot));
    if (t->inflight) t->inflight--;
    t->stats.inflight_packets = t->inflight;
    return true;
}

static void maybe_finish_ack_of_acks(RDPUDP2Transport *t, uint16_t sequence) {
    if (t->ack_of_acks_pending &&
        sequence_delta(sequence, t->ack_of_acks_sequence) >= 0)
        t->ack_of_acks_pending = false;
}

static size_t acknowledge_through(RDPUDP2Transport *t, uint16_t sequence,
                                  uint64_t now_ms, uint32_t ack_delay_ms) {
    size_t acknowledged = 0;
    for (size_t i = 0; i < RDPUDP2_WINDOW_SIZE; ++i) {
        RDPUDP2TxSlot *slot = &t->tx[i];
        if (!slot->used || sequence_delta(slot->data_sequence, sequence) > 0)
            continue;
        bool exact = slot->data_sequence == sequence;
        if (acknowledge_one(t, slot->data_sequence, now_ms, ack_delay_ms, exact))
            acknowledged++;
    }
    congestion_on_ack(t, acknowledged);
    maybe_finish_ack_of_acks(t, sequence);
    return acknowledged;
}

static void process_ack_vector(RDPUDP2Transport *t,
                               const RDPUDP2AckVector *vector,
                               uint64_t now_ms) {
    bool states[127u * 7u];
    size_t state_count = 0;
    for (uint8_t i = 0; i < vector->encoded_size; i++) {
        uint8_t value = vector->encoded[i];
        if (!(value & 0x80)) {
            for (unsigned bit = 0; bit < 7; ++bit)
                states[state_count++] = (value & (1u << bit)) != 0;
        } else {
            unsigned count = value & 0x3f;
            bool received = (value & 0x40) != 0;
            for (unsigned j = 0; j < count && state_count < sizeof(states); ++j)
                states[state_count++] = received;
        }
    }

    size_t highest_received = SIZE_MAX;
    for (size_t i = 0; i < state_count; ++i)
        if (states[i]) highest_received = i;

    size_t acknowledged = 0;
    for (size_t i = 0; i < state_count; ++i) {
        if (!states[i]) continue;
        uint16_t sequence = (uint16_t)(vector->base_sequence + i);
        bool sample = vector->timestamp_present && i == highest_received;
        if (acknowledge_one(t, sequence, now_ms,
                            sample ? vector->send_gap_ms : 0, sample))
            acknowledged++;
    }
    congestion_on_ack(t, acknowledged);

    if (highest_received != SIZE_MAX) {
        for (size_t i = 0; i < highest_received; ++i) {
            if (!states[i] && highest_received - i >=
                                  RDPUDP2_FAST_RETRANSMIT_THRESHOLD) {
                t->fast_loss_pending = true;
                t->fast_loss_sequence =
                    (uint16_t)(vector->base_sequence + i);
                break;
            }
        }
    }
    if (t->ack_of_acks_pending &&
        sequence_delta(vector->base_sequence, t->ack_of_acks_sequence) > 0)
        t->ack_of_acks_pending = false;
}

static RDPUDP2AckRxSlot *ack_rx_slot(RDPUDP2Transport *t, uint16_t sequence) {
    return &t->ack_rx[sequence & (RDPUDP2_WINDOW_SIZE - 1u)];
}

static bool ack_window_has_gap(const RDPUDP2Transport *t) {
    if (!t->ack_window_active) return false;
    uint16_t sequence = t->ack_base_sequence;
    for (;;) {
        const RDPUDP2AckRxSlot *slot =
            &t->ack_rx[sequence & (RDPUDP2_WINDOW_SIZE - 1u)];
        if (!slot->valid || slot->data_sequence != sequence || !slot->received)
            return true;
        if (sequence == t->ack_highest_sequence) return false;
        sequence++;
    }
}

static size_t ack_window_length(const RDPUDP2Transport *t) {
    return t->ack_window_active
               ? (size_t)(uint16_t)(t->ack_highest_sequence -
                                    t->ack_base_sequence) + 1u
               : 0;
}

static void clear_ack_window(RDPUDP2Transport *t) {
    if (t->ack_window_active) {
        uint16_t sequence = t->ack_base_sequence;
        for (;;) {
            RDPUDP2AckRxSlot *slot = ack_rx_slot(t, sequence);
            if (slot->valid && slot->data_sequence == sequence)
                memset(slot, 0, sizeof(*slot));
            if (sequence == t->ack_highest_sequence) break;
            sequence++;
        }
    }
    t->ack_window_active = false;
    t->pending_ack_count = 0;
    t->first_unacknowledged_ms = 0;
}

typedef enum {
    ACK_MARK_NEW,
    ACK_MARK_DUPLICATE,
    ACK_MARK_OLD,
    ACK_MARK_INVALID,
} AckMarkResult;

static AckMarkResult mark_received_for_ack(RDPUDP2Transport *t,
                                           uint16_t sequence,
                                           uint64_t now_ms) {
    if (!t->ack_window_active) {
        uint16_t base = sequence;
        if (t->ack_floor_valid) {
            int16_t from_floor = sequence_delta(sequence,
                                                t->ack_floor_sequence);
            if (from_floor < 0) return ACK_MARK_OLD;
            if ((uint16_t)from_floor >= RDPUDP2_WINDOW_SIZE)
                return ACK_MARK_INVALID;
            base = t->ack_floor_sequence;
        }
        t->ack_window_active = true;
        t->ack_base_sequence = base;
        t->ack_highest_sequence = sequence;
        uint16_t cursor = base;
        for (;;) {
            RDPUDP2AckRxSlot *slot = ack_rx_slot(t, cursor);
            *slot = (RDPUDP2AckRxSlot){
                .valid = true,
                .received = cursor == sequence,
                .data_sequence = cursor,
                .received_at_ms = cursor == sequence ? now_ms : 0,
            };
            if (cursor == sequence) break;
            cursor++;
        }
        return ACK_MARK_NEW;
    }

    int16_t from_base = sequence_delta(sequence, t->ack_base_sequence);
    if (from_base < 0) return ACK_MARK_OLD;
    int16_t above_highest = sequence_delta(sequence, t->ack_highest_sequence);
    if (above_highest >= (int16_t)RDPUDP2_WINDOW_SIZE)
        return ACK_MARK_INVALID;
    if (above_highest > 0) {
        uint16_t cursor = (uint16_t)(t->ack_highest_sequence + 1u);
        for (;;) {
            RDPUDP2AckRxSlot *slot = ack_rx_slot(t, cursor);
            *slot = (RDPUDP2AckRxSlot){
                .valid = true,
                .received = cursor == sequence,
                .data_sequence = cursor,
                .received_at_ms = cursor == sequence ? now_ms : 0,
            };
            if (cursor == sequence) break;
            cursor++;
        }
        t->ack_highest_sequence = sequence;
        return ACK_MARK_NEW;
    }

    RDPUDP2AckRxSlot *slot = ack_rx_slot(t, sequence);
    if (!slot->valid || slot->data_sequence != sequence)
        return ACK_MARK_INVALID;
    if (slot->received) return ACK_MARK_DUPLICATE;
    slot->received = true;
    slot->received_at_ms = now_ms;
    return ACK_MARK_NEW;
}

static bool send_ack_value(RDPUDP2Transport *t, uint16_t sequence,
                           uint64_t received_at_ms, uint64_t now_ms,
                           const uint8_t *additions, uint8_t addition_count,
                           uint8_t addition_scale, bool delayed) {
    RDPUDP2Packet ack = {0};
    ack.flags = RDPUDP2_FLAG_ACK;
    ack.log_window_size = t->local_log_window;
    ack.ack.sequence = sequence;
    ack.ack.received_timestamp = timestamp_4us(received_at_ms);
    ack.ack.send_gap_ms = saturating_gap_ms(now_ms, received_at_ms);
    ack.ack.delayed_count = addition_count;
    ack.ack.delayed_scale = addition_scale;
    ack.ack.delayed_additions = additions;
    add_sender_controls(t, &ack);
    uint8_t wire[RDPUDP2_MAX_DATAGRAM];
    size_t wire_length = 0;
    bool sent = rdpudp2_encode(&ack, wire, &wire_length) &&
                send_wire(t, wire, wire_length, now_ms, false);
    if (sent) {
        note_sender_controls_sent(t, &ack, now_ms);
        t->stats.acknowledgements_sent++;
        if (delayed) t->stats.delayed_acknowledgements_sent++;
    }
    return sent;
}

static bool send_cumulative_ack_through(RDPUDP2Transport *t,
                                        uint16_t highest_sequence,
                                        uint64_t now_ms) {
    if (!t->ack_window_active) return false;
    int16_t offset = sequence_delta(highest_sequence, t->ack_base_sequence);
    if (offset < 0 || (uint16_t)offset >= RDPUDP2_WINDOW_SIZE) return false;
    size_t total = (size_t)(uint16_t)offset + 1u;
    if (total > 16u) return false;
    uint16_t cursor = t->ack_base_sequence;
    for (;;) {
        RDPUDP2AckRxSlot *slot = ack_rx_slot(t, cursor);
        if (!slot->valid || slot->data_sequence != cursor || !slot->received)
            return false;
        if (cursor == highest_sequence) break;
        cursor++;
    }
    uint8_t count = total > 1u ? (uint8_t)(total - 1u) : 0;
    uint64_t newest_time = ack_rx_slot(t, highest_sequence)->received_at_ms;
    uint64_t gaps_us[15] = {0};
    uint64_t maximum_gap = 0;
    for (uint8_t i = 0; i < count; ++i) {
        uint16_t newer = (uint16_t)(highest_sequence - i);
        uint16_t older = (uint16_t)(newer - 1u);
        uint64_t newer_time = ack_rx_slot(t, newer)->received_at_ms;
        uint64_t older_time = ack_rx_slot(t, older)->received_at_ms;
        gaps_us[i] = newer_time >= older_time
                         ? (newer_time - older_time) * 1000u : 0;
        if (gaps_us[i] > maximum_gap) maximum_gap = gaps_us[i];
    }
    uint8_t scale = 0;
    while (scale < 15u && ((maximum_gap + ((uint64_t)1u << scale) - 1u) >> scale) > 255u)
        ++scale;
    uint8_t additions[15] = {0};
    for (uint8_t i = 0; i < count; ++i) {
        uint64_t encoded = (gaps_us[i] + ((uint64_t)1u << scale) - 1u) >> scale;
        additions[i] = (uint8_t)(encoded > 255u ? 255u : encoded);
    }

    bool delayed = t->first_unacknowledged_ms &&
                   now_ms > t->first_unacknowledged_ms;
    if (!send_ack_value(t, highest_sequence, newest_time, now_ms,
                        additions, count, scale, delayed))
        return false;
    t->have_last_cumulative_ack = true;
    t->last_cumulative_ack = highest_sequence;
    t->last_cumulative_receive_ms = newest_time;
    t->ack_floor_valid = true;
    t->ack_floor_sequence = (uint16_t)(highest_sequence + 1u);

    if (highest_sequence == t->ack_highest_sequence) {
        clear_ack_window(t);
    } else {
        cursor = t->ack_base_sequence;
        for (;;) {
            RDPUDP2AckRxSlot *slot = ack_rx_slot(t, cursor);
            if (slot->valid && slot->data_sequence == cursor)
                memset(slot, 0, sizeof(*slot));
            if (cursor == highest_sequence) break;
            cursor++;
        }
        t->ack_base_sequence = (uint16_t)(highest_sequence + 1u);
        t->pending_ack_count = 0;
        t->first_unacknowledged_ms = 0;
    }
    return true;
}

static bool send_cumulative_ack(RDPUDP2Transport *t, uint64_t now_ms) {
    if (!t->ack_window_active || ack_window_has_gap(t)) return false;
    return send_cumulative_ack_through(t, t->ack_highest_sequence, now_ms);
}

static bool send_ack_vector(RDPUDP2Transport *t, uint64_t now_ms) {
    if (!t->ack_window_active) return false;

    /* ACK a received prefix separately so BaseSeqNum identifies the first
     * missing packet, as required by the receiver-window model. */
    RDPUDP2AckRxSlot *base_slot = ack_rx_slot(t, t->ack_base_sequence);
    if (base_slot->valid &&
        base_slot->data_sequence == t->ack_base_sequence &&
        base_slot->received) {
        uint16_t prefix_end = t->ack_base_sequence;
        while (prefix_end != t->ack_highest_sequence) {
            uint16_t next = (uint16_t)(prefix_end + 1u);
            RDPUDP2AckRxSlot *slot = ack_rx_slot(t, next);
            if (!slot->valid || slot->data_sequence != next || !slot->received)
                break;
            prefix_end = next;
        }
        if (!send_cumulative_ack_through(t, prefix_end, now_ms)) return false;
        if (!t->ack_window_active) return true;
    }

    size_t total = ack_window_length(t);
    size_t offset = 0;
    while (offset < total) {
        size_t chunk = total - offset;
        if (chunk > 840u) chunk = 840u;
        uint8_t encoded[127] = {0};
        uint8_t encoded_size = 0;
        size_t cursor = 0;
        while (chunk - cursor >= 7u) {
            uint8_t map = 0;
            for (unsigned bit = 0; bit < 7; ++bit) {
                uint16_t sequence = (uint16_t)(t->ack_base_sequence +
                                                offset + cursor + bit);
                RDPUDP2AckRxSlot *slot = ack_rx_slot(t, sequence);
                if (slot->valid && slot->data_sequence == sequence && slot->received)
                    map |= (uint8_t)(1u << bit);
            }
            encoded[encoded_size++] = map;
            cursor += 7u;
        }
        while (cursor < chunk) {
            uint16_t sequence = (uint16_t)(t->ack_base_sequence + offset + cursor);
            RDPUDP2AckRxSlot *slot = ack_rx_slot(t, sequence);
            bool state = slot->valid && slot->data_sequence == sequence && slot->received;
            size_t run = 1;
            while (cursor + run < chunk && run < 63u) {
                uint16_t next = (uint16_t)(sequence + run);
                RDPUDP2AckRxSlot *next_slot = ack_rx_slot(t, next);
                bool next_state = next_slot->valid &&
                                  next_slot->data_sequence == next &&
                                  next_slot->received;
                if (next_state != state) break;
                ++run;
            }
            encoded[encoded_size++] = (uint8_t)(0x80u | (state ? 0x40u : 0u) | run);
            cursor += run;
        }

        RDPUDP2Packet ack = {0};
        ack.flags = RDPUDP2_FLAG_ACKVEC;
        ack.log_window_size = t->local_log_window;
        ack.ack_vector.base_sequence =
            (uint16_t)(t->ack_base_sequence + offset);
        ack.ack_vector.encoded = encoded;
        ack.ack_vector.encoded_size = encoded_size;
        if (offset + chunk == total) {
            for (size_t i = chunk; i > 0; --i) {
                uint16_t sequence = (uint16_t)(t->ack_base_sequence +
                                                offset + i - 1u);
                RDPUDP2AckRxSlot *slot = ack_rx_slot(t, sequence);
                if (slot->valid && slot->data_sequence == sequence && slot->received) {
                    ack.ack_vector.timestamp_present = true;
                    ack.ack_vector.timestamp = timestamp_4us(slot->received_at_ms);
                    ack.ack_vector.send_gap_ms =
                        saturating_gap_ms(now_ms, slot->received_at_ms);
                    break;
                }
            }
        }
        add_sender_controls(t, &ack);
        uint8_t wire[RDPUDP2_MAX_DATAGRAM];
        size_t wire_length = 0;
        if (!rdpudp2_encode(&ack, wire, &wire_length) ||
            !send_wire(t, wire, wire_length, now_ms, false))
            return false;
        note_sender_controls_sent(t, &ack, now_ms);
        t->stats.acknowledgement_vectors_sent++;
        offset += chunk;
    }
    t->pending_ack_count = 0;
    t->first_unacknowledged_ms = 0;
    return true;
}

static void discard_ack_window_before(RDPUDP2Transport *t, uint16_t sequence) {
    /* AckOfAcks on the first peer packet only retires history that would have
     * existed before this receiver was created. It must not manufacture a
     * missing packet at the start of our acknowledgement window. */
    if (!t->ack_floor_valid && !t->ack_window_active) return;
    if (t->ack_floor_valid &&
        sequence_delta(sequence, t->ack_floor_sequence) < 0)
        return;
    t->ack_floor_valid = true;
    t->ack_floor_sequence = sequence;
    if (!t->ack_window_active) return;
    int16_t advance = sequence_delta(sequence, t->ack_base_sequence);
    if (advance <= 0) return;
    size_t length = ack_window_length(t);
    if ((size_t)advance >= length) {
        clear_ack_window(t);
        return;
    }
    uint16_t cursor = t->ack_base_sequence;
    while (cursor != sequence) {
        RDPUDP2AckRxSlot *slot = ack_rx_slot(t, cursor);
        if (slot->valid && slot->data_sequence == cursor)
            memset(slot, 0, sizeof(*slot));
        cursor++;
    }
    t->ack_base_sequence = sequence;
    t->pending_ack_count = 0;
    t->first_unacknowledged_ms = 0;
    uint16_t remaining = sequence;
    for (;;) {
        RDPUDP2AckRxSlot *slot = ack_rx_slot(t, remaining);
        if (slot->valid && slot->data_sequence == remaining && slot->received) {
            if (!t->pending_ack_count)
                t->first_unacknowledged_ms = slot->received_at_ms;
            t->pending_ack_count++;
            if (slot->received_at_ms < t->first_unacknowledged_ms)
                t->first_unacknowledged_ms = slot->received_at_ms;
        }
        if (remaining == t->ack_highest_sequence) break;
        remaining++;
    }
}

static bool acknowledge_received_data(RDPUDP2Transport *t, uint16_t sequence,
                                      uint64_t now_ms) {
    bool had_gap = ack_window_has_gap(t);
    AckMarkResult result = mark_received_for_ack(t, sequence, now_ms);
    if (result == ACK_MARK_INVALID) return false;
    if (result == ACK_MARK_OLD) {
        if (!t->have_last_cumulative_ack) return true;
        return send_ack_value(t, t->last_cumulative_ack,
                              t->last_cumulative_receive_ms, now_ms,
                              NULL, 0, 0, false);
    }
    if (result == ACK_MARK_DUPLICATE) {
        return ack_window_has_gap(t) ? send_ack_vector(t, now_ms) : true;
    }

    t->pending_ack_count++;
    if (!t->first_unacknowledged_ms) t->first_unacknowledged_ms = now_ms;
    bool has_gap = ack_window_has_gap(t);
    if (has_gap) return send_ack_vector(t, now_ms);
    if (had_gap || t->pending_ack_count >= t->peer_max_delayed_acks)
        return send_cumulative_ack(t, now_ms);
    return true;
}

static void deliver_ready(RDPUDP2Transport *t) {
    for (;;) {
        size_t index = t->next_receive_channel_sequence &
                       (RDPUDP2_WINDOW_SIZE - 1u);
        RDPUDP2RxSlot *slot = &t->rx[index];
        if (!slot->used ||
            slot->channel_sequence != t->next_receive_channel_sequence)
            return;
        t->deliver_stream(t->context, slot->payload, slot->payload_length);
        t->stats.stream_bytes_delivered += slot->payload_length;
        memset(slot, 0, sizeof(*slot));
        t->next_receive_channel_sequence =
            channel_sequence_after(t->next_receive_channel_sequence);
    }
}

bool rdpudp2_transport_receive(RDPUDP2Transport *t,
                               const uint8_t *datagram, size_t length,
                               uint64_t now_ms) {
    if (!t) return false;
    if (length > t->receive_mtu) {
        t->stats.malformed_datagrams++;
        return false;
    }
    uint8_t logical[RDPUDP2_MAX_DATAGRAM];
    RDPUDP2Packet packet;
    if (!rdpudp2_decode(datagram, length, logical, &packet)) {
        t->stats.malformed_datagrams++;
        return false;
    }
    t->stats.datagrams_received++;
    t->last_received_ms = now_ms;
    t->have_received = true;
    t->peer_log_window = bounded_peer_log(packet.log_window_size);

    if (packet.flags & RDPUDP2_FLAG_DELAY_ACK_INFO) {
        uint8_t maximum = packet.max_delayed_acks;
        if (maximum == 0) maximum = 1;
        if (maximum > 15) maximum = 15;
        uint16_t timeout = packet.delayed_ack_timeout_ms;
        if (timeout == 0) timeout = 1;
        if (timeout > RDPUDP2_MAX_DELAY_ACK_MS)
            timeout = RDPUDP2_MAX_DELAY_ACK_MS;
        t->peer_max_delayed_acks = maximum;
        t->peer_delayed_ack_timeout_ms = timeout;
    }
    if (packet.flags & RDPUDP2_FLAG_AOA) {
        discard_ack_window_before(t, packet.ack_of_acks_sequence);
        if (t->ack_window_active && !ack_window_has_gap(t) &&
            !send_cumulative_ack(t, now_ms))
            return false;
    }
    if (packet.flags & RDPUDP2_FLAG_ACK) {
        t->stats.acknowledgements_received++;
        acknowledge_through(t, packet.ack.sequence, now_ms,
                            packet.ack.send_gap_ms);
    }
    if (packet.flags & RDPUDP2_FLAG_ACKVEC) {
        t->stats.acknowledgement_vectors_received++;
        process_ack_vector(t, &packet.ack_vector, now_ms);
    }

    if (!(packet.flags & RDPUDP2_FLAG_DATA)) return true;
    if (!packet.dummy && packet.channel_sequence == 0) {
        t->stats.malformed_datagrams++;
        return false;
    }
    if (!acknowledge_received_data(t, packet.data_sequence, now_ms)) return false;
    if (packet.dummy) return true;

    int16_t delta = sequence_delta(packet.channel_sequence,
                                   t->next_receive_channel_sequence);
    if (delta < 0) {
        t->stats.duplicate_data++;
        return true;
    }
    if ((uint16_t)delta >= RDPUDP2_WINDOW_SIZE) return false;
    if (delta > 0) t->stats.out_of_order_data++;

    size_t index = packet.channel_sequence & (RDPUDP2_WINDOW_SIZE - 1u);
    RDPUDP2RxSlot *slot = &t->rx[index];
    if (slot->used) {
        if (slot->channel_sequence == packet.channel_sequence)
            t->stats.duplicate_data++;
        return slot->channel_sequence == packet.channel_sequence;
    }
    slot->used = true;
    slot->channel_sequence = packet.channel_sequence;
    slot->payload_length = packet.data_length;
    if (packet.data_length) memcpy(slot->payload, packet.data, packet.data_length);
    deliver_ready(t);
    return true;
}

static bool retransmit_slot(RDPUDP2Transport *t, size_t index,
                            uint64_t now_ms) {
    RDPUDP2TxSlot *slot = &t->tx[index];
    if (!slot->used || slot->retransmissions >= RDPUDP2_MAX_RETRANSMISSIONS)
        return false;
    t->data_sequence_to_slot[slot->data_sequence] = -1;
    slot->data_sequence = t->next_data_sequence++;
    slot->sent_at_ms = now_ms;
    slot->retransmissions++;
    t->data_sequence_to_slot[slot->data_sequence] = (int32_t)index;

    uint8_t wire[RDPUDP2_MAX_DATAGRAM];
    size_t wire_length = 0;
    RDPUDP2Packet packet;
    bool sent = encode_tx_slot(t, slot, wire, &wire_length, &packet) &&
                send_wire(t, wire, wire_length, now_ms, true);
    if (sent) note_sender_controls_sent(t, &packet, now_ms);
    return sent;
}

static bool send_ack_of_acks(RDPUDP2Transport *t, uint64_t now_ms) {
    if (!t->ack_of_acks_pending) return true;
    RDPUDP2Packet packet = {0};
    packet.flags = RDPUDP2_FLAG_AOA;
    packet.log_window_size = t->local_log_window;
    packet.ack_of_acks_sequence = t->ack_of_acks_sequence;
    if (t->delay_ack_advertisements_remaining) {
        packet.flags |= RDPUDP2_FLAG_DELAY_ACK_INFO;
        packet.max_delayed_acks = RDPUDP2_DEFAULT_DELAY_ACKS;
        packet.delayed_ack_timeout_ms = RDPUDP2_DEFAULT_DELAY_ACK_MS;
    }
    uint8_t wire[RDPUDP2_MAX_DATAGRAM];
    size_t wire_length = 0;
    bool sent = rdpudp2_encode(&packet, wire, &wire_length) &&
                send_wire(t, wire, wire_length, now_ms, false);
    if (sent) note_sender_controls_sent(t, &packet, now_ms);
    return sent;
}

static bool declare_lost_through(RDPUDP2Transport *t, uint16_t sequence,
                                 uint64_t now_ms, bool fast) {
    size_t indices[RDPUDP2_WINDOW_SIZE];
    size_t count = 0;
    bool have_survivor = false;
    uint16_t survivor_delta = 0;
    for (size_t i = 0; i < RDPUDP2_WINDOW_SIZE; ++i) {
        if (!t->tx[i].used) continue;
        int16_t delta = sequence_delta(t->tx[i].data_sequence, sequence);
        if (delta <= 0) {
            indices[count++] = i;
        } else if (!have_survivor || (uint16_t)delta < survivor_delta) {
            have_survivor = true;
            survivor_delta = (uint16_t)delta;
        }
    }
    if (!count) return true;
    congestion_on_loss(t, now_ms);
    t->ack_of_acks_pending = true;
    /* AckOfAcks names the new lowest packet still awaiting an ACK, not simply
     * the sequence after the loss. ACKVEC may already have removed a long run
     * of later packets, leaving the first retransmission as the true floor. */
    t->ack_of_acks_sequence = have_survivor
                                  ? (uint16_t)(sequence + survivor_delta)
                                  : t->next_data_sequence;
    for (size_t i = 0; i < count; ++i) {
        if (t->tx[indices[i]].retransmissions >= RDPUDP2_MAX_RETRANSMISSIONS) {
            t->stats.connection_timed_out = true;
            return false;
        }
        if (!retransmit_slot(t, indices[i], now_ms)) return false;
        if (fast)
            t->stats.fast_retransmissions++;
        else
            t->stats.timeout_retransmissions++;
    }
    /* retransmit_slot piggybacks the newly-created AckOfAcks state. */
    return true;
}

static bool send_keepalive(RDPUDP2Transport *t, uint64_t now_ms) {
    uint8_t zeros[100] = {0};
    RDPUDP2Packet packet = {0};
    packet.flags = RDPUDP2_FLAG_DATA;
    packet.log_window_size = t->local_log_window;
    packet.dummy = true;
    packet.data_sequence = t->next_data_sequence++;
    packet.channel_sequence = 0;
    packet.data = zeros;
    packet.data_length = sizeof(zeros);
    add_sender_controls(t, &packet);
    uint8_t wire[RDPUDP2_MAX_DATAGRAM];
    size_t wire_length = 0;
    bool sent = rdpudp2_encode(&packet, wire, &wire_length) &&
                send_wire(t, wire, wire_length, now_ms, false);
    if (sent) note_sender_controls_sent(t, &packet, now_ms);
    return sent;
}

static uint64_t slot_timeout_ms(const RDPUDP2Transport *t,
                                const RDPUDP2TxSlot *slot) {
    uint64_t timeout = t->retransmit_timeout_ms;
    unsigned shifts = slot->retransmissions > 8u ? 8u : slot->retransmissions;
    timeout <<= shifts;
    return timeout > RDPUDP2_MAX_RETRANSMIT_MS
               ? RDPUDP2_MAX_RETRANSMIT_MS : timeout;
}

bool rdpudp2_transport_tick(RDPUDP2Transport *t, uint64_t now_ms) {
    if (!t) return false;
    if (t->have_received && now_ms - t->last_received_ms >=
                                RDPUDP2_LOST_CONNECTION_MS) {
        t->stats.connection_timed_out = true;
        return false;
    }
    if (t->ack_window_active && t->pending_ack_count &&
        now_ms - t->first_unacknowledged_ms >=
            t->peer_delayed_ack_timeout_ms) {
        bool sent = ack_window_has_gap(t) ? send_ack_vector(t, now_ms)
                                          : send_cumulative_ack(t, now_ms);
        if (!sent) return false;
    }
    if (t->fast_loss_pending) {
        uint16_t sequence = t->fast_loss_sequence;
        t->fast_loss_pending = false;
        if (!declare_lost_through(t, sequence, now_ms, true)) return false;
    }
    for (size_t i = 0; i < RDPUDP2_WINDOW_SIZE; i++) {
        if (!t->tx[i].used) continue;
        if (now_ms - t->tx[i].sent_at_ms >= slot_timeout_ms(t, &t->tx[i])) {
            uint16_t sequence = t->tx[i].data_sequence;
            if (!declare_lost_through(t, sequence, now_ms, false)) return false;
            break;
        }
    }
    if (t->ack_of_acks_pending &&
        now_ms - t->last_ack_of_acks_sent_ms >= t->retransmit_timeout_ms &&
        !send_ack_of_acks(t, now_ms))
        return false;
    if (now_ms - t->last_sent_ms >= RDPUDP2_KEEPALIVE_MS)
        return send_keepalive(t, now_ms);
    return true;
}

void rdpudp2_transport_get_stats(const RDPUDP2Transport *t,
                                 RDPUDP2Stats *stats) {
    if (!stats) return;
    if (!t) {
        memset(stats, 0, sizeof(*stats));
        return;
    }
    *stats = t->stats;
    stats->inflight_packets = t->inflight;
    stats->smoothed_rtt_ms = t->smoothed_rtt_ms;
    stats->retransmit_timeout_ms = t->retransmit_timeout_ms;
    stats->congestion_window_packets = t->congestion_window;
}
