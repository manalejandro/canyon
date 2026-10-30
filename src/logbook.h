/*
 * logbook.h - logging of received data for canyon
 *
 * Everything received on the socket is persisted:
 *   - TCP: raw byte stream appended to outdir/stream-<tag>.log
 *   - UDP: one file per datagram under outdir/datagrams-<tag>/
 * In addition an events log (JSONL) records connections, errors and
 * per-datagram metadata.
 */

#ifndef CANYON_LOGBOOK_H
#define CANYON_LOGBOOK_H

#include "canyon.h"

#include <sys/socket.h>

/*
 * Observer sinks. When registered, every received byte and every event
 * is also forwarded to these callbacks (used by the ncurses TUI). They
 * are called from the sender/receiver threads and must be thread-safe
 * and non-blocking.
 */
typedef void (*logbook_bytes_sink_t)(const void *data, size_t n);
typedef void (*logbook_event_sink_t)(const char *type, const char *msg);

void logbook_set_stream_sink(logbook_bytes_sink_t fn);
void logbook_set_dgram_sink(logbook_bytes_sink_t fn);
void logbook_set_event_sink(logbook_event_sink_t fn);

/*
 * Prepare the log output directory and open the log files.
 * Returns 0 on success, -1 on failure.
 */
int logbook_init(protocol_t proto, const char *outdir, size_t max_log_bytes);

/* Append received bytes to the TCP stream log. */
void logbook_stream(const void *data, size_t n);

/* Save a received UDP datagram and record its metadata. */
void logbook_datagram(const void *data, size_t n,
                      const struct sockaddr *src, socklen_t srclen);

/* Append an event line to the events log. */
void logbook_event(const char *type, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Flush and close all log files. */
void logbook_close(void);

#endif /* CANYON_LOGBOOK_H */
