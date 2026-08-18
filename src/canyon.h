/*
 * canyon.h - common definitions for canyon
 *
 * canyon is a TCP/UDP socket flooding and fuzzing tool that pumps a
 * stream of random bytes (read from /dev/urandom or any file) into a
 * socket and logs everything that comes back.
 *
 * License: MIT. See the LICENSE file for details.
 */

#ifndef CANYON_H
#define CANYON_H

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define CANYON_VERSION "1.1.0"

#define DEFAULT_RANDOM_SOURCE "/dev/urandom"
#define DEFAULT_OUTDIR "canyon-logs"
#define DEFAULT_CHUNK 4096
#define DEFAULT_RECONNECT_DELAY_US 1000000L

typedef enum {
    PROTO_TCP,
    PROTO_UDP
} protocol_t;

typedef struct {
    /* target */
    char *host;
    int port;
    protocol_t proto;

    /* socks5 proxy (TCP only) */
    char *proxy_host;
    int proxy_port;
    char *proxy_user;
    char *proxy_pass;

    /* websocket / http */
    bool websocket;
    bool http;
    char *path;
    bool ws_text;

    /* tls */
    bool tls;
    bool tls_verify;
    char *tls_ca;
    char *sni;

    /* traffic shaping */
    char *random_source;
    size_t chunk_min;
    size_t chunk_max;
    long delay_min_us;
    long delay_max_us;
    int timeout_secs;
    unsigned long max_chunks;
    bool reconnect;
    long reconnect_delay_us;

    /* logging */
    char *outdir;
    size_t max_log_bytes;
    bool no_recv;
    bool recv_only;

    /* misc */
    bool verbose;
    bool quiet;
} options_t;

extern options_t opts;
extern volatile sig_atomic_t g_running;

void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void die(const char *fmt, ...) __attribute__((format(printf, 1, 2))) __attribute__((noreturn));

uint64_t now_ms(void);
void sleep_us(long us);
int mkdir_p(const char *path, mode_t mode);

/* Returns true when host is an IPv4/IPv6 literal (not a hostname). */
bool is_ip_literal(const char *host);

#endif /* CANYON_H */
