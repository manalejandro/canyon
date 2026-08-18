/*
 * logbook.c - logging of received data for canyon
 */

#include "canyon.h"
#include "logbook.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/time.h>

typedef struct {
    char outdir[PATH_MAX + 128];
    char tag[128];
    protocol_t proto;
    FILE *events;
    FILE *stream;
    char dgram_dir[PATH_MAX + 128];
    uint64_t seq;
    uint64_t stream_bytes;
    size_t max_log_bytes;
    int roll;
} logbook_t;

static logbook_t lb;

static void json_escape(FILE *f, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '"':
            fputs("\\\"", f);
            break;
        case '\\':
            fputs("\\\\", f);
            break;
        case '\n':
            fputs("\\n", f);
            break;
        case '\r':
            fputs("\\r", f);
            break;
        case '\t':
            fputs("\\t", f);
            break;
        default:
            fputc(*s, f);
            break;
        }
    }
}

int logbook_init(protocol_t proto, const char *outdir, size_t max_log_bytes)
{
    char tag[64];
    char path[2 * PATH_MAX + 128];
    struct timeval tv;
    struct tm tmv;

    memset(&lb, 0, sizeof lb);
    lb.proto = proto;
    lb.max_log_bytes = max_log_bytes;
    snprintf(lb.outdir, sizeof lb.outdir, "%s", outdir);

    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tmv);
    strftime(tag, sizeof tag, "%Y%m%d-%H%M%S", &tmv);
    snprintf(lb.tag, sizeof lb.tag, "%s-%d", tag, (int)getpid());

    if (mkdir_p(outdir, 0755) != 0)
        return -1;

    snprintf(path, sizeof path, "%s/events-%s.log", outdir, lb.tag);
    lb.events = fopen(path, "w");
    if (!lb.events)
        return -1;

    if (proto == PROTO_TCP) {
        snprintf(path, sizeof path, "%s/stream-%s.log", outdir, lb.tag);
        lb.stream = fopen(path, "wb");
        if (!lb.stream) {
            fclose(lb.events);
            lb.events = NULL;
            return -1;
        }
    } else {
        snprintf(lb.dgram_dir, sizeof lb.dgram_dir,
                 "%s/datagrams-%s", outdir, lb.tag);
        if (mkdir_p(lb.dgram_dir, 0755) != 0) {
            fclose(lb.events);
            lb.events = NULL;
            return -1;
        }
    }
    return 0;
}

void logbook_event(const char *type, const char *fmt, ...)
{
    char msg[1024];
    va_list ap;

    if (!lb.events)
        return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    fprintf(lb.events, "{\"ts\":%llu,\"type\":\"%s\",\"msg\":\"",
            (unsigned long long)now_ms(), type);
    json_escape(lb.events, msg);
    fprintf(lb.events, "\"}\n");
    fflush(lb.events);
}

void logbook_stream(const void *data, size_t n)
{
    char path[2 * PATH_MAX + 128];

    if (!lb.stream)
        return;

    if (lb.max_log_bytes > 0 &&
        lb.stream_bytes + n > lb.max_log_bytes) {
        fclose(lb.stream);
        lb.stream = NULL;
        lb.roll++;
        snprintf(path, sizeof path, "%s/stream-%s-%d.log",
                 lb.outdir, lb.tag, lb.roll);
        lb.stream = fopen(path, "wb");
        lb.stream_bytes = 0;
        if (!lb.stream)
            return;
    }

    fwrite(data, 1, n, lb.stream);
    fflush(lb.stream);
    lb.stream_bytes += n;
}

void logbook_datagram(const void *data, size_t n,
                      const struct sockaddr *src, socklen_t srclen)
{
    char path[2 * PATH_MAX + 128];
    char host[INET6_ADDRSTRLEN] = "?";
    uint16_t port = 0;

    if (!lb.dgram_dir[0])
        return;

    snprintf(path, sizeof path, "%s/d_%llu.bin",
             lb.dgram_dir, (unsigned long long)lb.seq);

    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, n, f);
        fclose(f);
    }

    if (src && src->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)src;
        inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
        port = ntohs(a->sin_port);
    } else if (src && src->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)src;
        inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof host);
        port = ntohs(a->sin6_port);
    }
    (void)srclen;

    logbook_event("datagram", "seq=%llu bytes=%zu src=%s:%u",
                  (unsigned long long)lb.seq, n, host, (unsigned)port);
    lb.seq++;
}

void logbook_close(void)
{
    if (lb.events) {
        fclose(lb.events);
        lb.events = NULL;
    }
    if (lb.stream) {
        fclose(lb.stream);
        lb.stream = NULL;
    }
}
