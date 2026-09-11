/*
 * Minimal reverse UDP relay for the macOS RDPUDP2 experiment.
 *
 * Unlike a conventional stream tunnel, every inner UDP datagram is carried in
 * exactly one outer UDP datagram.  Loss and reordering are therefore visible
 * to RDPUDP2 instead of being hidden behind another reliable byte stream.
 *
 * The relay is intentionally single-session: the isolated RDP endpoint accepts
 * one interactive client at a time.  Every tunnel packet is authenticated with
 * HMAC-SHA256 (truncated to 128 bits), and a 64-packet replay window preserves
 * harmless network reordering while rejecting duplicates.
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RELAY_MAGIC "RUR1"
#define RELAY_VERSION 1u
#define RELAY_HEADER_SIZE 40u
#define RELAY_TAG_SIZE 16u
#define RELAY_PREFIX_SIZE 24u
#define RELAY_MAX_INNER 1232u
#define RELAY_MAX_WIRE (RELAY_HEADER_SIZE + RELAY_MAX_INNER)
#define RELAY_KEY_MAX 512u
#define RELAY_SOCKET_BUFFER (4 * 1024 * 1024)
#define RELAY_TUNNEL_TIMEOUT_MS 12000u
#define RELAY_PEER_REPLACE_MS 10000u
#define RELAY_STATS_INTERVAL_MS 30000u

enum relay_type {
    RELAY_HELLO = 1,
    RELAY_WELCOME = 2,
    RELAY_PING = 3,
    RELAY_PONG = 4,
    RELAY_TO_LOCAL = 5,
    RELAY_TO_PUBLIC = 6,
};

typedef struct {
    uint32_t state[8];
    uint64_t bit_length;
    uint8_t block[64];
    size_t block_length;
} sha256_ctx;

typedef struct {
    uint8_t type;
    uint64_t session;
    uint64_t sequence;
    const uint8_t *payload;
    uint16_t payload_length;
} relay_packet;

typedef struct {
    uint64_t newest;
    uint64_t bitmap;
    int initialized;
} replay_window;

typedef struct {
    uint64_t public_rx;
    uint64_t public_tx;
    uint64_t tunnel_rx;
    uint64_t tunnel_tx;
    uint64_t auth_drop;
    uint64_t replay_drop;
    uint64_t peer_drop;
    uint64_t no_route_drop;
} relay_stats;

static volatile sig_atomic_t g_running = 1;

static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static uint32_t rotr32(uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32u - bits));
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
        size_t o = i * 4u;
        w[i] = ((uint32_t)block[o] << 24) |
               ((uint32_t)block[o + 1] << 16) |
               ((uint32_t)block[o + 2] << 8) |
               (uint32_t)block[o + 3];
    }
    for (size_t i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2];
    uint32_t d = ctx->state[3], e = ctx->state[4], f = ctx->state[5];
    uint32_t g = ctx->state[6], h = ctx->state[7];
    for (size_t i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + sha256_k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t length) {
    while (length > 0) {
        size_t available = 64u - ctx->block_length;
        size_t take = length < available ? length : available;
        memcpy(ctx->block + ctx->block_length, data, take);
        ctx->block_length += take;
        data += take;
        length -= take;
        if (ctx->block_length == 64u) {
            sha256_transform(ctx, ctx->block);
            ctx->bit_length += 512u;
            ctx->block_length = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t digest[32]) {
    ctx->bit_length += (uint64_t)ctx->block_length * 8u;
    ctx->block[ctx->block_length++] = 0x80u;
    if (ctx->block_length > 56u) {
        memset(ctx->block + ctx->block_length, 0, 64u - ctx->block_length);
        sha256_transform(ctx, ctx->block);
        ctx->block_length = 0;
    }
    memset(ctx->block + ctx->block_length, 0, 56u - ctx->block_length);
    for (size_t i = 0; i < 8; ++i)
        ctx->block[63u - i] = (uint8_t)(ctx->bit_length >> (i * 8u));
    sha256_transform(ctx, ctx->block);
    for (size_t i = 0; i < 8; ++i) {
        digest[i * 4u] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4u + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4u + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4u + 3] = (uint8_t)ctx->state[i];
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_length,
                        const uint8_t *first, size_t first_length,
                        const uint8_t *second, size_t second_length,
                        uint8_t digest[32]) {
    uint8_t normalized[64] = {0};
    if (key_length > sizeof(normalized)) {
        sha256_ctx key_hash;
        sha256_init(&key_hash);
        sha256_update(&key_hash, key, key_length);
        sha256_final(&key_hash, normalized);
    } else {
        memcpy(normalized, key, key_length);
    }

    uint8_t inner_pad[64], outer_pad[64], inner_digest[32];
    for (size_t i = 0; i < 64; ++i) {
        inner_pad[i] = normalized[i] ^ 0x36u;
        outer_pad[i] = normalized[i] ^ 0x5cu;
    }
    sha256_ctx inner;
    sha256_init(&inner);
    sha256_update(&inner, inner_pad, sizeof(inner_pad));
    sha256_update(&inner, first, first_length);
    if (second_length > 0) sha256_update(&inner, second, second_length);
    sha256_final(&inner, inner_digest);

    sha256_ctx outer;
    sha256_init(&outer);
    sha256_update(&outer, outer_pad, sizeof(outer_pad));
    sha256_update(&outer, inner_digest, sizeof(inner_digest));
    sha256_final(&outer, digest);

    memset(normalized, 0, sizeof(normalized));
    memset(inner_pad, 0, sizeof(inner_pad));
    memset(outer_pad, 0, sizeof(outer_pad));
    memset(inner_digest, 0, sizeof(inner_digest));
}

static void put_u16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void put_u64(uint8_t *p, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) p[7u - i] = (uint8_t)(value >> (i * 8u));
}

static uint64_t get_u64(const uint8_t *p) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}

static int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t difference = 0;
    for (size_t i = 0; i < n; ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}

static size_t encode_packet(uint8_t wire[RELAY_MAX_WIRE], uint8_t type,
                            uint64_t session, uint64_t sequence,
                            const uint8_t *payload, size_t payload_length,
                            const uint8_t *key, size_t key_length) {
    if (payload_length > RELAY_MAX_INNER) return 0;
    memcpy(wire, RELAY_MAGIC, 4);
    wire[4] = RELAY_VERSION;
    wire[5] = type;
    put_u16(wire + 6, (uint16_t)payload_length);
    put_u64(wire + 8, session);
    put_u64(wire + 16, sequence);
    if (payload_length > 0) memcpy(wire + RELAY_HEADER_SIZE, payload, payload_length);
    uint8_t digest[32];
    hmac_sha256(key, key_length, wire, RELAY_PREFIX_SIZE,
                wire + RELAY_HEADER_SIZE, payload_length, digest);
    memcpy(wire + RELAY_PREFIX_SIZE, digest, RELAY_TAG_SIZE);
    memset(digest, 0, sizeof(digest));
    return RELAY_HEADER_SIZE + payload_length;
}

static int decode_packet(const uint8_t *wire, size_t wire_length,
                         const uint8_t *key, size_t key_length,
                         relay_packet *packet) {
    if (wire_length < RELAY_HEADER_SIZE || memcmp(wire, RELAY_MAGIC, 4) != 0 ||
        wire[4] != RELAY_VERSION)
        return 0;
    uint16_t payload_length = get_u16(wire + 6);
    if (payload_length > RELAY_MAX_INNER ||
        wire_length != RELAY_HEADER_SIZE + (size_t)payload_length)
        return 0;
    uint8_t digest[32];
    hmac_sha256(key, key_length, wire, RELAY_PREFIX_SIZE,
                wire + RELAY_HEADER_SIZE, payload_length, digest);
    int valid = constant_time_equal(wire + RELAY_PREFIX_SIZE, digest, RELAY_TAG_SIZE);
    memset(digest, 0, sizeof(digest));
    if (!valid) return 0;
    packet->type = wire[5];
    if (packet->type < RELAY_HELLO || packet->type > RELAY_TO_PUBLIC)
        return 0;
    if (packet->type <= RELAY_PONG && payload_length != 0)
        return 0;
    packet->session = get_u64(wire + 8);
    packet->sequence = get_u64(wire + 16);
    if (packet->session == 0 || packet->sequence == 0) return 0;
    packet->payload = wire + RELAY_HEADER_SIZE;
    packet->payload_length = payload_length;
    return 1;
}

static int replay_accept(replay_window *window, uint64_t sequence) {
    if (!window->initialized) {
        window->initialized = 1;
        window->newest = sequence;
        window->bitmap = 1u;
        return 1;
    }
    if (sequence > window->newest) {
        uint64_t advance = sequence - window->newest;
        window->bitmap = advance >= 64u ? 1u : (window->bitmap << advance) | 1u;
        window->newest = sequence;
        return 1;
    }
    uint64_t distance = window->newest - sequence;
    if (distance >= 64u) return 0;
    uint64_t bit = UINT64_C(1) << distance;
    if ((window->bitmap & bit) != 0) return 0;
    window->bitmap |= bit;
    return 1;
}

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t random_u64(void) {
    uint64_t value = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t got = read(fd, &value, sizeof(value));
        close(fd);
        if (got == (ssize_t)sizeof(value) && value != 0) return value;
    }
    value = ((uint64_t)time(NULL) << 32) ^ (uint64_t)getpid() ^ monotonic_ms();
    return value != 0 ? value : 1;
}

static void signal_handler(int signal_number) {
    (void)signal_number;
    g_running = 0;
}

static int parse_port(const char *text) {
    char *end = NULL;
    long value = strtol(text, &end, 10);
    return end && *end == '\0' && value >= 1 && value <= 65535 ? (int)value : -1;
}

static int read_key(const char *path, uint8_t key[RELAY_KEY_MAX], size_t *key_length) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "token file is not a regular file: %s\n", path);
        return 0;
    }
    FILE *file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "cannot open token file %s: %s\n", path, strerror(errno));
        return 0;
    }
    size_t length = fread(key, 1, RELAY_KEY_MAX, file);
    int extra = fgetc(file);
    fclose(file);
    if (extra != EOF) {
        fprintf(stderr, "token file is too large\n");
        return 0;
    }
    size_t start = 0;
    while (start < length && (key[start] == ' ' || key[start] == '\t' ||
                              key[start] == '\r' || key[start] == '\n'))
        ++start;
    while (length > start && (key[length - 1] == ' ' || key[length - 1] == '\t' ||
                              key[length - 1] == '\r' || key[length - 1] == '\n'))
        --length;
    if (start > 0) memmove(key, key + start, length - start);
    length -= start;
    if (length < 16u) {
        fprintf(stderr, "token must contain at least 16 bytes\n");
        memset(key, 0, RELAY_KEY_MAX);
        return 0;
    }
    *key_length = length;
    return 1;
}

static int configure_socket(int fd) {
    int size = RELAY_SOCKET_BUFFER;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int bind_udp(const char *address, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int reuse = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in bind_address;
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, address, &bind_address.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) != 0 ||
        !configure_socket(fd)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_udp(const char *host, int port, const char *bind_address) {
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%d", port);
    struct addrinfo hints, *addresses = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port_text, &hints, &addresses) != 0) return -1;
    int fd = -1;
    for (struct addrinfo *it = addresses; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        if (bind_address) {
            struct sockaddr_in local;
            memset(&local, 0, sizeof(local));
            local.sin_family = AF_INET;
            local.sin_port = 0;
            if (inet_pton(AF_INET, bind_address, &local.sin_addr) != 1 ||
                bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0 && configure_socket(fd)) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    return fd;
}

static int address_equal(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_family == b->sin_family && a->sin_port == b->sin_port &&
           a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static void address_text(const struct sockaddr_in *address, char *output, size_t length) {
    char host[INET_ADDRSTRLEN] = "?";
    (void)inet_ntop(AF_INET, &address->sin_addr, host, sizeof(host));
    snprintf(output, length, "%s:%u", host, (unsigned)ntohs(address->sin_port));
}

static int send_relay(int fd, const struct sockaddr_in *destination,
                      uint8_t type, uint64_t session, uint64_t sequence,
                      const uint8_t *payload, size_t payload_length,
                      const uint8_t *key, size_t key_length) {
    uint8_t wire[RELAY_MAX_WIRE];
    size_t length = encode_packet(wire, type, session, sequence, payload,
                                  payload_length, key, key_length);
    if (length == 0) return 0;
    ssize_t sent = destination
                       ? sendto(fd, wire, length, 0,
                                (const struct sockaddr *)destination, sizeof(*destination))
                       : send(fd, wire, length, 0);
    return sent == (ssize_t)length;
}

static void log_stats(const char *mode, const relay_stats *stats) {
    fprintf(stderr,
            "%s stats public_rx=%llu public_tx=%llu tunnel_rx=%llu tunnel_tx=%llu "
            "auth_drop=%llu replay_drop=%llu peer_drop=%llu no_route_drop=%llu\n",
            mode,
            (unsigned long long)stats->public_rx,
            (unsigned long long)stats->public_tx,
            (unsigned long long)stats->tunnel_rx,
            (unsigned long long)stats->tunnel_tx,
            (unsigned long long)stats->auth_drop,
            (unsigned long long)stats->replay_drop,
            (unsigned long long)stats->peer_drop,
            (unsigned long long)stats->no_route_drop);
}

typedef struct {
    int public_fd;
    int tunnel_fd;
    const uint8_t *key;
    size_t key_length;
    struct sockaddr_in tunnel_peer;
    struct sockaddr_in public_peer;
    int tunnel_valid;
    int public_valid;
    uint64_t session;
    uint64_t outgoing_sequence;
    uint64_t last_tunnel_ms;
    uint64_t last_public_ms;
    replay_window incoming;
    relay_stats stats;
} relay_server_state;

static int looks_like_relay_wire(const uint8_t *wire, size_t length) {
    if (length < RELAY_HEADER_SIZE || memcmp(wire, RELAY_MAGIC, 4) != 0 ||
        wire[4] != RELAY_VERSION)
        return 0;
    uint16_t payload_length = get_u16(wire + 6);
    return payload_length <= RELAY_MAX_INNER &&
           length == RELAY_HEADER_SIZE + (size_t)payload_length;
}

static void server_handle_public(relay_server_state *state,
                                 const uint8_t *payload, size_t length,
                                 const struct sockaddr_in *source,
                                 uint64_t now) {
    ++state->stats.public_rx;
    if (!state->tunnel_valid ||
        now - state->last_tunnel_ms > RELAY_TUNNEL_TIMEOUT_MS) {
        state->tunnel_valid = 0;
        ++state->stats.no_route_drop;
        return;
    }
    if (state->public_valid &&
        !address_equal(source, &state->public_peer) &&
        now - state->last_public_ms < RELAY_PEER_REPLACE_MS) {
        ++state->stats.peer_drop;
        return;
    }
    if (!state->public_valid || !address_equal(source, &state->public_peer)) {
        state->public_peer = *source;
        state->public_valid = 1;
        char peer[64];
        address_text(&state->public_peer, peer, sizeof(peer));
        fprintf(stderr, "active public RDP peer: %s\n", peer);
    }
    state->last_public_ms = now;
    if (send_relay(state->tunnel_fd, &state->tunnel_peer, RELAY_TO_LOCAL,
                   state->session, state->outgoing_sequence++, payload, length,
                   state->key, state->key_length))
        ++state->stats.tunnel_tx;
    else
        ++state->stats.no_route_drop;
}

static void server_handle_tunnel(relay_server_state *state,
                                 const relay_packet *packet,
                                 const struct sockaddr_in *source,
                                 uint64_t now) {
    ++state->stats.tunnel_rx;
    if (packet->type == RELAY_HELLO) {
        int changed = !state->tunnel_valid ||
                      packet->session != state->session ||
                      !address_equal(source, &state->tunnel_peer);
        if (changed && state->tunnel_valid &&
            now - state->last_tunnel_ms < RELAY_PEER_REPLACE_MS) {
            ++state->stats.peer_drop;
            return;
        }
        if (changed) {
            memset(&state->incoming, 0, sizeof(state->incoming));
            state->outgoing_sequence = 1;
        }
        if (!replay_accept(&state->incoming, packet->sequence)) {
            ++state->stats.replay_drop;
            return;
        }
        state->tunnel_peer = *source;
        state->tunnel_valid = 1;
        state->session = packet->session;
        state->last_tunnel_ms = now;
        if (changed) {
            state->public_valid = 0;
            char peer[64];
            address_text(&state->tunnel_peer, peer, sizeof(peer));
            fprintf(stderr, "authenticated tunnel client: %s session=%016llx\n",
                    peer, (unsigned long long)state->session);
        }
        if (send_relay(state->tunnel_fd, &state->tunnel_peer, RELAY_WELCOME,
                       state->session, state->outgoing_sequence++, NULL, 0,
                       state->key, state->key_length))
            ++state->stats.tunnel_tx;
        return;
    }
    if (!state->tunnel_valid || packet->session != state->session ||
        !address_equal(source, &state->tunnel_peer)) {
        ++state->stats.peer_drop;
        return;
    }
    if (!replay_accept(&state->incoming, packet->sequence)) {
        ++state->stats.replay_drop;
        return;
    }
    state->last_tunnel_ms = now;
    if (packet->type == RELAY_PING) {
        if (send_relay(state->tunnel_fd, &state->tunnel_peer, RELAY_PONG,
                       state->session, state->outgoing_sequence++, NULL, 0,
                       state->key, state->key_length))
            ++state->stats.tunnel_tx;
    } else if (packet->type == RELAY_TO_PUBLIC) {
        if (!state->public_valid) {
            ++state->stats.no_route_drop;
        } else {
            ssize_t sent = sendto(state->public_fd, packet->payload,
                                  packet->payload_length, 0,
                                  (struct sockaddr *)&state->public_peer,
                                  sizeof(state->public_peer));
            if (sent == packet->payload_length)
                ++state->stats.public_tx;
            else
                ++state->stats.no_route_drop;
        }
    } else {
        ++state->stats.peer_drop;
    }
}

static int run_server(const char *bind_address, int public_port, int tunnel_port,
                      const uint8_t *key, size_t key_length) {
    int shared_port = public_port == tunnel_port;
    int public_fd = bind_udp(bind_address, public_port);
    int tunnel_fd = shared_port ? public_fd : bind_udp(bind_address, tunnel_port);
    if (public_fd < 0 || tunnel_fd < 0) {
        fprintf(stderr, "failed to bind UDP public=%d tunnel=%d: %s\n",
                public_port, tunnel_port, strerror(errno));
        if (public_fd >= 0) close(public_fd);
        if (tunnel_fd >= 0 && tunnel_fd != public_fd) close(tunnel_fd);
        return 1;
    }

    if (shared_port)
        fprintf(stderr, "server listening: UDP %s:%d shared public+tunnel\n",
                bind_address, public_port);
    else
        fprintf(stderr, "server listening: UDP %s:%d public, UDP %s:%d tunnel\n",
                bind_address, public_port, bind_address, tunnel_port);
    relay_server_state state = {
        .public_fd = public_fd,
        .tunnel_fd = tunnel_fd,
        .key = key,
        .key_length = key_length,
        .outgoing_sequence = 1,
    };
    uint64_t last_stats_ms = monotonic_ms();
    relay_stats last_logged_stats = {0};
    struct pollfd fds[2] = {
        {.fd = public_fd, .events = POLLIN},
        {.fd = tunnel_fd, .events = POLLIN},
    };

    while (g_running) {
        int ready = poll(fds, shared_port ? 1u : 2u, 100);
        if (ready < 0 && errno != EINTR) break;
        uint64_t now = monotonic_ms();

        if (shared_port && (fds[0].revents & POLLIN)) {
            for (unsigned batch = 0; batch < 256; ++batch) {
                uint8_t wire[RELAY_MAX_WIRE];
                struct sockaddr_in source;
                socklen_t source_length = sizeof(source);
                ssize_t length = recvfrom(public_fd, wire, sizeof(wire), 0,
                                          (struct sockaddr *)&source, &source_length);
                if (length < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                        fprintf(stderr, "shared recv failed: %s\n", strerror(errno));
                    break;
                }
                relay_packet packet;
                if (decode_packet(wire, (size_t)length, key, key_length,
                                  &packet)) {
                    server_handle_tunnel(&state, &packet, &source, now);
                } else if (looks_like_relay_wire(wire, (size_t)length)) {
                    ++state.stats.auth_drop;
                } else if ((size_t)length <= RELAY_MAX_INNER) {
                    server_handle_public(&state, wire, (size_t)length,
                                         &source, now);
                } else {
                    ++state.stats.auth_drop;
                }
            }
        } else if (!shared_port && (fds[0].revents & POLLIN)) {
            for (unsigned batch = 0; batch < 256; ++batch) {
                uint8_t payload[RELAY_MAX_INNER];
                struct sockaddr_in source;
                socklen_t source_length = sizeof(source);
                ssize_t length = recvfrom(public_fd, payload, sizeof(payload), 0,
                                          (struct sockaddr *)&source, &source_length);
                if (length < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                        fprintf(stderr, "public recv failed: %s\n", strerror(errno));
                    break;
                }
                server_handle_public(&state, payload, (size_t)length, &source, now);
            }
        }

        if (!shared_port && (fds[1].revents & POLLIN)) {
            for (unsigned batch = 0; batch < 256; ++batch) {
                uint8_t wire[RELAY_MAX_WIRE];
                struct sockaddr_in source;
                socklen_t source_length = sizeof(source);
                ssize_t length = recvfrom(tunnel_fd, wire, sizeof(wire), 0,
                                          (struct sockaddr *)&source, &source_length);
                if (length < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                        fprintf(stderr, "tunnel recv failed: %s\n", strerror(errno));
                    break;
                }
                relay_packet packet;
                if (!decode_packet(wire, (size_t)length, key, key_length, &packet)) {
                    ++state.stats.auth_drop;
                    continue;
                }
                server_handle_tunnel(&state, &packet, &source, now);
            }
        }

        if (state.tunnel_valid &&
            now - state.last_tunnel_ms > RELAY_TUNNEL_TIMEOUT_MS) {
            fprintf(stderr, "tunnel client timed out\n");
            state.tunnel_valid = 0;
            state.public_valid = 0;
        }
        if (now - last_stats_ms >= RELAY_STATS_INTERVAL_MS) {
            if (memcmp(&state.stats, &last_logged_stats,
                       sizeof(state.stats)) != 0) {
                log_stats("server", &state.stats);
                last_logged_stats = state.stats;
            }
            last_stats_ms = now;
        }
    }

    close(public_fd);
    if (tunnel_fd != public_fd) close(tunnel_fd);
    return 0;
}

static int run_client(const char *server, int tunnel_port, const char *local_address,
                      int local_port, const uint8_t *key, size_t key_length) {
    int tunnel_fd = connect_udp(server, tunnel_port, NULL);
    int local_fd = connect_udp(local_address, local_port, local_address);
    if (tunnel_fd < 0 || local_fd < 0) {
        fprintf(stderr, "failed to open client sockets: %s\n", strerror(errno));
        if (tunnel_fd >= 0) close(tunnel_fd);
        if (local_fd >= 0) close(local_fd);
        return 1;
    }

    uint64_t session = random_u64(), outgoing_sequence = 1;
    uint64_t last_hello_ms = 0, last_ping_ms = 0, last_server_ms = 0;
    uint64_t last_stats_ms = monotonic_ms();
    int registered = 0;
    replay_window incoming = {0};
    relay_stats stats = {0};
    relay_stats last_logged_stats = {0};
    struct pollfd fds[2] = {
        {.fd = tunnel_fd, .events = POLLIN},
        {.fd = local_fd, .events = POLLIN},
    };
    fprintf(stderr, "client forwarding UDP %s:%d through %s:%d session=%016llx\n",
            local_address, local_port, server, tunnel_port,
            (unsigned long long)session);

    while (g_running) {
        uint64_t now = monotonic_ms();
        if (!registered && (last_hello_ms == 0 || now - last_hello_ms >= 1000u)) {
            if (send_relay(tunnel_fd, NULL, RELAY_HELLO, session,
                           outgoing_sequence++, NULL, 0, key, key_length))
                ++stats.tunnel_tx;
            last_hello_ms = now;
        } else if (registered && now - last_ping_ms >= 2000u) {
            if (send_relay(tunnel_fd, NULL, RELAY_PING, session,
                           outgoing_sequence++, NULL, 0, key, key_length))
                ++stats.tunnel_tx;
            last_ping_ms = now;
        }

        int ready = poll(fds, 2, 100);
        if (ready < 0 && errno != EINTR) break;
        now = monotonic_ms();

        if (fds[0].revents & POLLIN) {
            for (unsigned batch = 0; batch < 256; ++batch) {
                uint8_t wire[RELAY_MAX_WIRE];
                ssize_t length = recv(tunnel_fd, wire, sizeof(wire), 0);
                if (length < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                        fprintf(stderr, "tunnel recv failed: %s\n", strerror(errno));
                    break;
                }
                relay_packet packet;
                if (!decode_packet(wire, (size_t)length, key, key_length, &packet)) {
                    ++stats.auth_drop;
                    continue;
                }
                ++stats.tunnel_rx;
                if (packet.session != session) {
                    ++stats.peer_drop;
                    continue;
                }
                if (packet.type == RELAY_WELCOME) {
                    if (!replay_accept(&incoming, packet.sequence)) {
                        ++stats.replay_drop;
                        continue;
                    }
                    if (!registered) {
                        fprintf(stderr, "UDP tunnel authenticated\n");
                        registered = 1;
                    }
                    last_server_ms = now;
                    continue;
                }
                if (!registered) {
                    ++stats.peer_drop;
                    continue;
                }
                if (!replay_accept(&incoming, packet.sequence)) {
                    ++stats.replay_drop;
                    continue;
                }
                last_server_ms = now;
                if (packet.type == RELAY_TO_LOCAL) {
                    ssize_t sent = send(local_fd, packet.payload,
                                        packet.payload_length, 0);
                    if (sent == packet.payload_length)
                        ++stats.public_tx;
                    else
                        ++stats.no_route_drop;
                } else if (packet.type != RELAY_PONG) {
                    ++stats.peer_drop;
                }
            }
        }

        if (fds[1].revents & POLLIN) {
            for (unsigned batch = 0; batch < 256; ++batch) {
                uint8_t payload[RELAY_MAX_INNER];
                ssize_t length = recv(local_fd, payload, sizeof(payload), 0);
                if (length < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                        fprintf(stderr, "local recv failed: %s\n", strerror(errno));
                    break;
                }
                ++stats.public_rx;
                if (!registered) {
                    ++stats.no_route_drop;
                    continue;
                }
                if (send_relay(tunnel_fd, NULL, RELAY_TO_PUBLIC, session,
                               outgoing_sequence++, payload, (size_t)length,
                               key, key_length))
                    ++stats.tunnel_tx;
                else
                    ++stats.no_route_drop;
            }
        }

        if (registered && now - last_server_ms > RELAY_TUNNEL_TIMEOUT_MS) {
            fprintf(stderr, "UDP tunnel timed out; re-registering\n");
            registered = 0;
            session = random_u64();
            outgoing_sequence = 1;
            last_hello_ms = 0;
            memset(&incoming, 0, sizeof(incoming));
        }
        if (now - last_stats_ms >= RELAY_STATS_INTERVAL_MS) {
            if (memcmp(&stats, &last_logged_stats, sizeof(stats)) != 0) {
                log_stats("client", &stats);
                last_logged_stats = stats;
            }
            last_stats_ms = now;
        }
    }

    close(tunnel_fd);
    close(local_fd);
    return 0;
}

static int self_test(void) {
    static const uint8_t expected_hmac[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    uint8_t rfc_key[20], rfc_digest[32];
    memset(rfc_key, 0x0b, sizeof(rfc_key));
    static const uint8_t rfc_data[] = "Hi There";
    hmac_sha256(rfc_key, sizeof(rfc_key), rfc_data, sizeof(rfc_data) - 1u,
                NULL, 0, rfc_digest);
    if (!constant_time_equal(rfc_digest, expected_hmac, sizeof(expected_hmac)))
        return 1;

    static const uint8_t key[] = "0123456789abcdef0123456789abcdef";
    static const uint8_t payload[] = {0x00, 0x11, 0x22, 0x7f, 0x80, 0xff};
    uint8_t wire[RELAY_MAX_WIRE];
    size_t length = encode_packet(wire, RELAY_TO_LOCAL,
                                  UINT64_C(0x0123456789abcdef), 42,
                                  payload, sizeof(payload), key, sizeof(key) - 1u);
    relay_packet decoded;
    if (length != RELAY_HEADER_SIZE + sizeof(payload) ||
        !decode_packet(wire, length, key, sizeof(key) - 1u, &decoded) ||
        decoded.type != RELAY_TO_LOCAL || decoded.sequence != 42 ||
        decoded.session != UINT64_C(0x0123456789abcdef) ||
        decoded.payload_length != sizeof(payload) ||
        memcmp(decoded.payload, payload, sizeof(payload)) != 0)
        return 1;
    wire[RELAY_HEADER_SIZE + 1] ^= 0x40u;
    if (decode_packet(wire, length, key, sizeof(key) - 1u, &decoded)) return 1;

    length = encode_packet(wire, 99, 1, 1, NULL, 0,
                           key, sizeof(key) - 1u);
    if (decode_packet(wire, length, key, sizeof(key) - 1u, &decoded)) return 1;
    length = encode_packet(wire, RELAY_HELLO, 1, 1, payload, sizeof(payload),
                           key, sizeof(key) - 1u);
    if (decode_packet(wire, length, key, sizeof(key) - 1u, &decoded)) return 1;
    length = encode_packet(wire, RELAY_PING, 0, 1, NULL, 0,
                           key, sizeof(key) - 1u);
    if (decode_packet(wire, length, key, sizeof(key) - 1u, &decoded)) return 1;
    length = encode_packet(wire, RELAY_PING, 1, 0, NULL, 0,
                           key, sizeof(key) - 1u);
    if (decode_packet(wire, length, key, sizeof(key) - 1u, &decoded)) return 1;

    replay_window window = {0};
    if (!replay_accept(&window, 100) || !replay_accept(&window, 102) ||
        !replay_accept(&window, 101) || replay_accept(&window, 101) ||
        replay_accept(&window, 1))
        return 1;
    puts("rdp-udp-relay self-test passed");
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage:\n"
            "  %s server --token-file PATH [--bind ADDRESS] [--public-port 43393] "
            "[--tunnel-port 43393]\n"
            "  %s client --token-file PATH --server HOST [--tunnel-port 43393] "
            "[--local-address 127.0.0.1] [--local-port 3392]\n"
            "  %s --self-test\n",
            program, program, program);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();
    if (argc < 2 || (strcmp(argv[1], "server") != 0 && strcmp(argv[1], "client") != 0)) {
        usage(argv[0]);
        return 2;
    }

    int is_server = strcmp(argv[1], "server") == 0;
    const char *token_file = NULL;
    const char *server = NULL;
    const char *bind_address = "0.0.0.0";
    const char *local_address = "127.0.0.1";
    int public_port = 43393, tunnel_port = 43393, local_port = 3392;
    for (int i = 2; i < argc; ++i) {
        if (i + 1 >= argc) {
            usage(argv[0]);
            return 2;
        }
        const char *value = argv[++i];
        if (strcmp(argv[i - 1], "--token-file") == 0)
            token_file = value;
        else if (strcmp(argv[i - 1], "--server") == 0)
            server = value;
        else if (strcmp(argv[i - 1], "--bind") == 0)
            bind_address = value;
        else if (strcmp(argv[i - 1], "--local-address") == 0)
            local_address = value;
        else if (strcmp(argv[i - 1], "--public-port") == 0)
            public_port = parse_port(value);
        else if (strcmp(argv[i - 1], "--tunnel-port") == 0)
            tunnel_port = parse_port(value);
        else if (strcmp(argv[i - 1], "--local-port") == 0)
            local_port = parse_port(value);
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!token_file || (!is_server && !server) || public_port < 0 ||
        tunnel_port < 0 || local_port < 0) {
        usage(argv[0]);
        return 2;
    }

    uint8_t key[RELAY_KEY_MAX] = {0};
    size_t key_length = 0;
    if (!read_key(token_file, key, &key_length)) return 1;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);

    int result = is_server
                     ? run_server(bind_address, public_port, tunnel_port,
                                  key, key_length)
                     : run_client(server, tunnel_port, local_address, local_port,
                                  key, key_length);
    memset(key, 0, sizeof(key));
    return result;
}
