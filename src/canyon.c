/*
 * canyon.c - TCP/UDP socket flooding and fuzzing tool
 *
 * canyon pumps a stream of random bytes (from /dev/urandom or any other
 * file, e.g. /dev/random) into a TCP or UDP socket and logs every byte
 * that comes back. Optionally the TCP traffic can be routed through a
 * SOCKS5 proxy.
 *
 * License: MIT. See the LICENSE file for details.
 */

#include "canyon.h"
#include "logbook.h"
#include "net.h"
#include "rand.h"
#include "socks5.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/time.h>

options_t opts;
volatile sig_atomic_t g_running = 1;

static int g_randfd = -1;
static int g_fd = -1;
static unsigned long g_sent = 0;
static bool g_random_dead = false;

#define CONNECT_TIMEOUT_MS 10000
#define DRAIN_MS 200

static const char *usage_text =
    "canyon - TCP/UDP socket flooding / fuzzing tool that feeds a random byte\n"
    "stream from /dev/urandom (or any file) into a socket and logs responses.\n"
    "\n"
    "Usage: canyon [options]\n"
    "\n"
    "Target:\n"
    "  -H, --host <host>          target host (default 127.0.0.1)\n"
    "  -p, --port <port>          target port (required)\n"
    "  -u, --udp                  use UDP instead of TCP\n"
    "\n"
    "Proxy:\n"
    "  -x, --socks5 <host:port>   route TCP traffic through a SOCKS5 proxy\n"
    "  -U, --socks5-user <user>   SOCKS5 username (RFC 1929 auth)\n"
    "  -P, --socks5-pass <pass>   SOCKS5 password\n"
    "\n"
    "Traffic shaping:\n"
    "  -r, --random-source <file> file to read random bytes from\n"
    "                             (default /dev/urandom; /dev/random works too)\n"
    "  -c, --chunk <MIN[-MAX]>    bytes per chunk sent to the socket\n"
    "                             (default 4096; ranges pick a random size)\n"
    "  -d, --delay <MIN[-MAX]>    delay between chunks in microseconds\n"
    "  -t, --timeout <secs>       stop after N seconds (0 = unlimited)\n"
    "  -n, --count <N>            send at most N chunks (0 = unlimited)\n"
    "  -R, --reconnect            reconnect when a TCP connection drops\n"
    "  -D, --reconnect-delay <us> delay before reconnecting (default 1000000)\n"
    "\n"
    "Logging:\n"
    "  -o, --outdir <dir>         output directory (default canyon-logs)\n"
    "  -m, --max-log <bytes>      max size per received-data log file\n"
    "  -N, --no-recv              do not read anything from the socket\n"
    "  -E, --recv-only            only read from the socket, do not send\n"
    "\n"
    "Misc:\n"
    "  -v, --verbose              verbose output\n"
    "  -q, --quiet                suppress informational output\n"
    "  -V, --version              print version and exit\n"
    "  -h, --help                 show this help and exit\n"
    "\n"
    "Examples:\n"
    "  canyon -p 8080                        flood a local HTTP port over TCP\n"
    "  canyon -u -p 53 -H 8.8.8.8 -c 512      flood 8.8.8.8:53 over UDP\n"
    "  canyon -p 8080 -x 127.0.0.1:1080       go through a local SOCKS5 proxy\n"
    "  canyon -p 3306 -R -d 1000-10000        reconnect after each drop\n"
    "\n"
    "Legal: use only against systems you own or are explicitly authorized to test.\n";

void logmsg(const char *fmt, ...)
{
    struct timeval tv;
    struct tm tmv;
    char ts[32];
    va_list ap;

    if (opts.quiet)
        return;

    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tmv);
    strftime(ts, sizeof ts, "%H:%M:%S", &tmv);

    fprintf(stderr, "[%s.%03ld] ", ts, tv.tv_usec / 1000);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

uint64_t now_ms(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

void sleep_us(long us)
{
    struct timespec ts;

    if (us <= 0)
        return;
    ts.tv_sec = us / 1000000L;
    ts.tv_nsec = (us % 1000000L) * 1000L;
    nanosleep(&ts, NULL);
}

int mkdir_p(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    char *p;

    snprintf(tmp, sizeof tmp, "%s", path);
    size_t len = strlen(tmp);
    if (len == 0)
        return -1;
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
    if (g_fd >= 0)
        shutdown(g_fd, SHUT_RDWR);
}

static int parse_u64_range(const char *s, unsigned long *lo, unsigned long *hi)
{
    char *end;
    unsigned long a;

    errno = 0;
    a = strtoul(s, &end, 10);
    if (end == s || errno)
        return -1;

    if (*end == '-') {
        unsigned long b;
        errno = 0;
        b = strtoul(end + 1, &end, 10);
        if (errno || *end != '\0' || b < a)
            return -1;
        *lo = a;
        *hi = b;
    } else if (*end == '\0') {
        *lo = a;
        *hi = a;
    } else {
        return -1;
    }
    return 0;
}

static int parse_socks5(const char *s)
{
    const char *colon = strrchr(s, ':');

    if (colon && (colon == s || strspn(colon + 1, "0123456789") == strlen(colon + 1))) {
        size_t hl = (size_t)(colon - s);
        if (hl == 0)
            return -1;
        opts.proxy_host = strndup(s, hl);
        opts.proxy_port = atoi(colon + 1);
    } else {
        opts.proxy_host = strdup(s);
        opts.proxy_port = 1080;
    }
    if (opts.proxy_port <= 0 || opts.proxy_port > 65535)
        return -1;
    return 0;
}

static const struct option long_opts[] = {
    { "host",            required_argument, 0, 'H' },
    { "port",            required_argument, 0, 'p' },
    { "udp",             no_argument,       0, 'u' },
    { "socks5",          required_argument, 0, 'x' },
    { "socks5-user",     required_argument, 0, 'U' },
    { "socks5-pass",     required_argument, 0, 'P' },
    { "random-source",   required_argument, 0, 'r' },
    { "chunk",           required_argument, 0, 'c' },
    { "delay",           required_argument, 0, 'd' },
    { "timeout",         required_argument, 0, 't' },
    { "count",           required_argument, 0, 'n' },
    { "outdir",          required_argument, 0, 'o' },
    { "reconnect",       no_argument,       0, 'R' },
    { "reconnect-delay", required_argument, 0, 'D' },
    { "no-recv",         no_argument,       0, 'N' },
    { "recv-only",       no_argument,       0, 'E' },
    { "max-log",         required_argument, 0, 'm' },
    { "verbose",         no_argument,       0, 'v' },
    { "quiet",           no_argument,       0, 'q' },
    { "version",         no_argument,       0, 'V' },
    { "help",            no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
};

typedef struct {
    int fd;
    protocol_t proto;
} recv_args_t;

static void *receiver_thread(void *arg)
{
    recv_args_t *a = arg;
    char buf[65536];

    for (;;) {
        struct pollfd p;
        p.fd = a->fd;
        p.events = POLLIN;
        int pr = poll(&p, 1, 1000);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pr == 0) {
            if (!g_running)
                break;
            continue;
        }

        ssize_t n;
        if (a->proto == PROTO_TCP) {
            n = recv(a->fd, buf, sizeof buf, 0);
        } else {
            struct sockaddr_in6 src;
            socklen_t sl = sizeof src;
            n = recvfrom(a->fd, buf, sizeof buf, 0,
                         (struct sockaddr *)&src, &sl);
            if (n >= 0)
                logbook_datagram(buf, (size_t)n, (struct sockaddr *)&src, sl);
        }

        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        if (n == 0)
            break;

        if (a->proto == PROTO_TCP)
            logbook_stream(buf, (size_t)n);

        if (opts.verbose)
            logmsg("received %zd bytes", n);
    }
    return NULL;
}

static bool over_budget(uint64_t start_ms)
{
    if (opts.timeout_secs > 0 &&
        now_ms() - start_ms >= (uint64_t)opts.timeout_secs * 1000)
        return true;
    if (opts.max_chunks > 0 && g_sent >= opts.max_chunks)
        return true;
    return false;
}

/* Returns 0 on a clean stop, -1 on a socket or random-source error. */
static int sender_loop(int fd, uint64_t start_ms)
{
    if (opts.recv_only) {
        while (g_running && !over_budget(start_ms))
            sleep_us(100000);
        return 0;
    }

    size_t bufcap = opts.chunk_max ? opts.chunk_max : 1;
    char *buf = malloc(bufcap);
    if (!buf) {
        logbook_event("error", "out of memory");
        return -1;
    }

    int rc = 0;
    while (g_running && !over_budget(start_ms)) {
        size_t want = (size_t)rand_range_u(opts.chunk_min, opts.chunk_max);
        int got = rand_fill(g_randfd, buf, want);
        if (got < 0) {
            logbook_event("random_error", "reading random source: %s",
                          strerror(errno));
            g_random_dead = true;
            rc = -1;
            break;
        }
        if ((size_t)got == 0) {
            logbook_event("random_eof", "random source exhausted");
            g_random_dead = true;
            rc = -1;
            break;
        }
        if ((size_t)got < want)
            logbook_event("random_short", "got %d of %zu bytes from source",
                          got, want);

        ssize_t r = send(fd, buf, (size_t)got, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            logbook_event("send_error", "%s", strerror(errno));
            rc = -1;
            break;
        }

        g_sent++;
        if (opts.verbose)
            logmsg("chunk %lu sent (%zd bytes)", g_sent, r);

        long d = (long)rand_range_u((uint64_t)opts.delay_min_us,
                                    (uint64_t)opts.delay_max_us);
        if (d > 0)
            sleep_us(d);
    }

    free(buf);
    return rc;
}

static int tcp_session(void)
{
    char err[256];
    uint64_t start = now_ms();
    int rc = 0;

    while (g_running && !over_budget(start)) {
        int fd;

        if (opts.proxy_host) {
            fd = net_connect_tcp(opts.proxy_host, opts.proxy_port,
                                 CONNECT_TIMEOUT_MS, err, sizeof err);
            if (fd >= 0 &&
                socks5_handshake(fd, opts.host, opts.port,
                                 opts.proxy_user, opts.proxy_pass,
                                 err, sizeof err) != 0) {
                logbook_event("socks5_error", "%s", err);
                close(fd);
                fd = -1;
            }
        } else {
            fd = net_connect_tcp(opts.host, opts.port,
                                 CONNECT_TIMEOUT_MS, err, sizeof err);
        }

        if (fd < 0) {
            logbook_event("connect_error", "%s", err);
            if (opts.verbose)
                logmsg("connect failed: %s", err);
            if (!opts.reconnect)
                return 1;
            if (g_running)
                sleep_us(opts.reconnect_delay_us);
            continue;
        }

        g_fd = fd;
        logbook_event("connect", "connected to %s:%d %s",
                      opts.host, opts.port,
                      opts.proxy_host ? "(via socks5)" : "");
        if (opts.verbose)
            logmsg("connected to %s:%d %s", opts.host, opts.port,
                   opts.proxy_host ? "(via socks5)" : "");

        pthread_t tid;
        recv_args_t a;
        bool have_recv = !opts.no_recv;
        a.fd = fd;
        a.proto = PROTO_TCP;
        if (have_recv && pthread_create(&tid, NULL, receiver_thread, &a) != 0)
            have_recv = false;

        sender_loop(fd, start);

        if (have_recv && g_running && !g_random_dead)
            sleep_us(DRAIN_MS * 1000);
        shutdown(fd, SHUT_RDWR);
        if (have_recv)
            pthread_join(tid, NULL);
        close(fd);
        g_fd = -1;

        logbook_event("disconnect", "connection closed");
        if (opts.verbose)
            logmsg("connection closed");

        if (g_random_dead) {
            rc = 1;
            break;
        }
        if (!opts.reconnect) {
            rc = 0;
            break;
        }
        if (g_running && !over_budget(start))
            sleep_us(opts.reconnect_delay_us);
    }
    return rc;
}

static int udp_session(void)
{
    char err[256];
    uint64_t start = now_ms();
    int fd;

    fd = net_connect_udp(opts.host, opts.port, err, sizeof err);
    if (fd < 0) {
        logbook_event("connect_error", "%s", err);
        if (opts.verbose)
            logmsg("connect failed: %s", err);
        return 1;
    }

    g_fd = fd;
    logbook_event("connect", "connected to %s:%d (udp)", opts.host, opts.port);
    if (opts.verbose)
        logmsg("connected to %s:%d (udp)", opts.host, opts.port);

    pthread_t tid;
    recv_args_t a;
    bool have_recv = !opts.no_recv;
    a.fd = fd;
    a.proto = PROTO_UDP;
    if (have_recv && pthread_create(&tid, NULL, receiver_thread, &a) != 0)
        have_recv = false;

    sender_loop(fd, start);

    if (have_recv && g_running && !g_random_dead)
        sleep_us(DRAIN_MS * 1000);
    shutdown(fd, SHUT_RDWR);
    if (have_recv)
        pthread_join(tid, NULL);
    close(fd);
    g_fd = -1;

    logbook_event("disconnect", "udp session ended");
    if (opts.verbose)
        logmsg("udp session ended");

    return g_random_dead ? 1 : 0;
}

static void run_sessions(void)
{
    int rc = (opts.proto == PROTO_TCP) ? tcp_session() : udp_session();
    logbook_event("end", "shutting down (sent=%lu rc=%d)", g_sent, rc);
    if (opts.verbose)
        logmsg("done: %lu chunks sent", g_sent);
}

int main(int argc, char **argv)
{
    int c;

    opts.host = "127.0.0.1";
    opts.port = 0;
    opts.proto = PROTO_TCP;
    opts.random_source = DEFAULT_RANDOM_SOURCE;
    opts.chunk_min = DEFAULT_CHUNK;
    opts.chunk_max = DEFAULT_CHUNK;
    opts.delay_min_us = 0;
    opts.delay_max_us = 0;
    opts.timeout_secs = 0;
    opts.max_chunks = 0;
    opts.outdir = DEFAULT_OUTDIR;
    opts.reconnect_delay_us = DEFAULT_RECONNECT_DELAY_US;
    opts.max_log_bytes = 0;

    while ((c = getopt_long(argc, argv,
                            "H:p:ux:U:P:r:c:d:t:n:o:RD:NEvmqVh",
                            long_opts, NULL)) != -1) {
        switch (c) {
        case 'H':
            opts.host = optarg;
            break;
        case 'p':
            opts.port = atoi(optarg);
            break;
        case 'u':
            opts.proto = PROTO_UDP;
            break;
        case 'x':
            if (parse_socks5(optarg) != 0)
                die("error: invalid --socks5 value '%s' (use host:port)", optarg);
            break;
        case 'U':
            opts.proxy_user = optarg;
            break;
        case 'P':
            opts.proxy_pass = optarg;
            break;
        case 'r':
            opts.random_source = optarg;
            break;
        case 'c': {
            unsigned long lo, hi;
            if (parse_u64_range(optarg, &lo, &hi) != 0 ||
                lo == 0 || hi > (1u << 20))
                die("error: invalid --chunk '%s' (use MIN[-MAX], 1..1048576)",
                    optarg);
            opts.chunk_min = (size_t)lo;
            opts.chunk_max = (size_t)hi;
            break;
        }
        case 'd': {
            unsigned long lo, hi;
            if (parse_u64_range(optarg, &lo, &hi) != 0)
                die("error: invalid --delay '%s' (use MIN[-MAX] microseconds)",
                    optarg);
            opts.delay_min_us = (long)lo;
            opts.delay_max_us = (long)hi;
            break;
        }
        case 't':
            opts.timeout_secs = atoi(optarg);
            if (opts.timeout_secs < 0)
                opts.timeout_secs = 0;
            break;
        case 'n':
            opts.max_chunks = strtoul(optarg, NULL, 10);
            break;
        case 'o':
            opts.outdir = optarg;
            break;
        case 'R':
            opts.reconnect = true;
            break;
        case 'D':
            opts.reconnect_delay_us = (long)strtoul(optarg, NULL, 10);
            break;
        case 'N':
            opts.no_recv = true;
            break;
        case 'E':
            opts.recv_only = true;
            break;
        case 'm':
            opts.max_log_bytes = (size_t)strtoull(optarg, NULL, 10);
            break;
        case 'v':
            opts.verbose = true;
            break;
        case 'q':
            opts.quiet = true;
            break;
        case 'V':
            printf("canyon %s\n", CANYON_VERSION);
            return 0;
        case 'h':
            fputs(usage_text, stdout);
            return 0;
        default:
            fputs(usage_text, stderr);
            return 2;
        }
    }

    if (opts.port <= 0 || opts.port > 65535)
        die("error: a valid --port (1-65535) is required");
    if (opts.recv_only && opts.no_recv)
        die("error: --recv-only and --no-recv are mutually exclusive");
    if (opts.proto == PROTO_UDP && opts.proxy_host)
        die("error: SOCKS5 proxy is only supported for TCP "
            "(UDP ASSOCIATE is not implemented)");
    if ((opts.proxy_user || opts.proxy_pass) && !opts.proxy_host)
        die("error: --socks5-user/--socks5-pass require --socks5");
    if (opts.recv_only && opts.max_chunks > 0)
        die("error: --count has no effect with --recv-only");
    if (opts.verbose && opts.quiet)
        die("error: --verbose and --quiet are mutually exclusive");

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    g_randfd = rand_open_source(opts.random_source);
    if (g_randfd < 0)
        die("error: cannot open random source '%s': %s",
            opts.random_source, strerror(errno));

    uint8_t seed[16];
    int got = rand_fill(g_randfd, seed, sizeof seed);
    if (got <= 0) {
        uint64_t a = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
        memcpy(seed, &a, sizeof a);
        memcpy(seed + sizeof a, &a, sizeof a);
    }
    rand_seed(seed, sizeof seed);

    if (logbook_init(opts.proto, opts.outdir, opts.max_log_bytes) != 0)
        die("error: cannot initialize log directory '%s': %s",
            opts.outdir, strerror(errno));

    if (!opts.quiet) {
        fprintf(stderr,
                "canyon %s - flooding %s:%d over %s%s\n",
                CANYON_VERSION, opts.host, opts.port,
                opts.proto == PROTO_TCP ? "TCP" : "UDP",
                opts.proxy_host ? " via SOCKS5" : "");
        fprintf(stderr,
                "  random source: %s   chunk: %zu-%zu bytes   delay: %ld-%ld us\n",
                opts.random_source, opts.chunk_min, opts.chunk_max,
                opts.delay_min_us, opts.delay_max_us);
        fprintf(stderr, "  logs: %s\n", opts.outdir);
    }

    logbook_event("start", "canyon %s target=%s:%d proto=%s%s",
                  CANYON_VERSION, opts.host, opts.port,
                  opts.proto == PROTO_TCP ? "tcp" : "udp",
                  opts.proxy_host ? " via socks5" : "");

    run_sessions();

    logbook_close();
    close(g_randfd);
    return 0;
}
