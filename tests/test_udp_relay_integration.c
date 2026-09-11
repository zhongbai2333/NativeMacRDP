#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_DATAGRAM 1232u

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void sleep_ms(long milliseconds) {
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (milliseconds % 1000) * 1000000L,
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static int bind_loopback(uint16_t requested_port, uint16_t *actual_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(requested_port),
        .sin_addr.s_addr = htonl(UINT32_C(0x7f000001)),
    };
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    socklen_t length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length) != 0) {
        close(fd);
        return -1;
    }
    if (actual_port) *actual_port = ntohs(address.sin_port);
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static pid_t start_relay(const char *executable, int server_mode,
                         const char *token, uint16_t public_port,
                         uint16_t tunnel_port, uint16_t local_port) {
    char public_text[16], tunnel_text[16], local_text[16];
    snprintf(public_text, sizeof(public_text), "%u", public_port);
    snprintf(tunnel_text, sizeof(tunnel_text), "%u", tunnel_port);
    snprintf(local_text, sizeof(local_text), "%u", local_port);

    pid_t child = fork();
    if (child != 0) return child;
    if (server_mode) {
        execl(executable, executable, "server", "--token-file", token,
              "--bind", "127.0.0.1", "--public-port", public_text,
              "--tunnel-port", tunnel_text, (char *)NULL);
    } else {
        execl(executable, executable, "client", "--token-file", token,
              "--server", "127.0.0.1", "--tunnel-port", tunnel_text,
              "--local-address", "127.0.0.1", "--local-port", local_text,
              (char *)NULL);
    }
    perror("execl relay");
    _exit(127);
}

static void stop_child(pid_t child) {
    if (child <= 0) return;
    (void)kill(child, SIGTERM);
    for (unsigned attempt = 0; attempt < 40; ++attempt) {
        int status = 0;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return;
        if (result < 0 && errno == ECHILD) return;
        sleep_ms(25);
    }
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, 0);
}

static void drain_socket(int fd) {
    uint8_t discarded[MAX_DATAGRAM];
    for (;;) {
        ssize_t length = recv(fd, discarded, sizeof(discarded), 0);
        if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (length <= 0) return;
    }
}

static int exchange_datagram(int public_fd, int local_fd,
                             const struct sockaddr_in *server,
                             size_t payload_length, uint8_t tag) {
    fprintf(stderr, "exchange start: %zu-byte datagram tag=0x%02x\n",
            payload_length, tag);
    uint8_t payload[MAX_DATAGRAM], response[MAX_DATAGRAM], received[MAX_DATAGRAM];
    for (size_t i = 0; i < payload_length; ++i)
        payload[i] = (uint8_t)(tag + (uint8_t)(i * 29u));
    for (size_t i = 0; i < payload_length; ++i)
        response[i] = payload[i] ^ 0xa5u;

    uint64_t deadline = monotonic_ms() + 6000u;
    uint64_t next_send = 0;
    int replied = 0;
    while (monotonic_ms() < deadline) {
        uint64_t now = monotonic_ms();
        if (!replied && now >= next_send) {
            ssize_t sent = sendto(public_fd, payload, payload_length, 0,
                                  (const struct sockaddr *)server, sizeof(*server));
            if (sent != (ssize_t)payload_length) return 0;
            next_send = now + 100u;
        }

        struct pollfd fds[2] = {
            {.fd = local_fd, .events = POLLIN},
            {.fd = public_fd, .events = POLLIN},
        };
        int ready = poll(fds, 2, 50);
        if (ready < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (fds[0].revents & POLLIN) {
            struct sockaddr_in relay_peer;
            socklen_t peer_length = sizeof(relay_peer);
            ssize_t length = recvfrom(local_fd, received, sizeof(received), 0,
                                      (struct sockaddr *)&relay_peer, &peer_length);
            if (length == (ssize_t)payload_length &&
                memcmp(received, payload, payload_length) == 0) {
                ssize_t sent = sendto(local_fd, response, payload_length, 0,
                                      (struct sockaddr *)&relay_peer, peer_length);
                if (sent != (ssize_t)payload_length) return 0;
                replied = 1;
            }
        }
        if (fds[1].revents & POLLIN) {
            ssize_t length = recv(public_fd, received, sizeof(received), 0);
            if (length == (ssize_t)payload_length &&
                memcmp(received, response, payload_length) == 0) {
                sleep_ms(150);
                drain_socket(local_fd);
                drain_socket(public_fd);
                fprintf(stderr, "exchange passed: %zu-byte datagram\n",
                        payload_length);
                return 1;
            }
        }
    }
    fprintf(stderr, "exchange timed out: %zu-byte datagram replied=%d\n",
            payload_length, replied);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/rdp-udp-relay\n", argv[0]);
        return 2;
    }
    fprintf(stderr, "integration setup: creating token\n");

    char token_path[] = "/private/tmp/rdp-udp-relay-test.XXXXXX";
#if !defined(__APPLE__)
    memcpy(token_path, "/tmp/rdp-udp-relay-test.XXXXXX",
           sizeof("/tmp/rdp-udp-relay-test.XXXXXX"));
#endif
    int token_fd = mkstemp(token_path);
    if (token_fd < 0) {
        perror("mkstemp");
        return 1;
    }
    static const char token[] = "local-integration-token-32-bytes!!\n";
    if (fchmod(token_fd, 0600) != 0 ||
        write(token_fd, token, sizeof(token) - 1u) != (ssize_t)(sizeof(token) - 1u)) {
        perror("write token");
        close(token_fd);
        unlink(token_path);
        return 1;
    }
    close(token_fd);

    fprintf(stderr, "integration setup: allocating loopback ports\n");
    uint16_t public_port = 0;
    int public_reservation = bind_loopback(0, &public_port);
    uint16_t tunnel_port = public_port;
    uint16_t local_port = 0;
    int local_fd = bind_loopback(0, &local_port);
    int public_fd = bind_loopback(0, NULL);
    if (public_reservation < 0 || local_fd < 0 || public_fd < 0) {
        fprintf(stderr, "failed to allocate loopback UDP ports\n");
        if (public_reservation >= 0) close(public_reservation);
        if (local_fd >= 0) close(local_fd);
        if (public_fd >= 0) close(public_fd);
        unlink(token_path);
        return 1;
    }
    close(public_reservation);

    fprintf(stderr, "integration setup: starting server on %u/%u\n",
            public_port, tunnel_port);
    pid_t server = start_relay(argv[1], 1, token_path, public_port,
                               tunnel_port, local_port);
    sleep_ms(75);
    fprintf(stderr, "integration setup: starting client for local %u\n",
            local_port);
    pid_t client = start_relay(argv[1], 0, token_path, public_port,
                               tunnel_port, local_port);
    if (server < 0 || client < 0) {
        perror("fork relay");
        stop_child(client);
        stop_child(server);
        close(local_fd);
        close(public_fd);
        unlink(token_path);
        return 1;
    }
    fprintf(stderr, "integration setup complete: server=%ld client=%ld\n",
            (long)server, (long)client);

    struct sockaddr_in relay_public = {
        .sin_family = AF_INET,
        .sin_port = htons(public_port),
        .sin_addr.s_addr = htonl(UINT32_C(0x7f000001)),
    };
    int passed = exchange_datagram(public_fd, local_fd, &relay_public,
                                   MAX_DATAGRAM, 0x31u);
    if (passed)
        passed = exchange_datagram(public_fd, local_fd, &relay_public,
                                   40u, 0x72u);
    if (passed)
        passed = exchange_datagram(public_fd, local_fd, &relay_public,
                                   1u, 0xc4u);

    stop_child(client);
    stop_child(server);
    close(local_fd);
    close(public_fd);
    unlink(token_path);
    if (!passed) {
        fprintf(stderr, "native UDP relay loopback integration failed\n");
        return 1;
    }
    puts("native UDP relay loopback integration passed (1232/40/1-byte datagrams)");
    return 0;
}
