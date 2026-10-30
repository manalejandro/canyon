/*
 * tui.h - interactive ncurses interface for canyon
 *
 * The TUI takes over the terminal and shows, without flooding stdout:
 *   - a title/status bar (target, mode, connection state);
 *   - live counters (sent/received bytes and messages, rates, uptime);
 *   - a scrollable hexdump (or text) view of every byte received;
 *   - a scrollable event log (connects, errors, ws/http metadata, ...).
 *
 * Feeds are thread-safe and bounded: the UI keeps the last 1 MiB of
 * received data and the last 1024 events and repaints at a fixed rate,
 * no matter how fast data arrives. Disk logging is unaffected.
 *
 * When the TUI is not (or cannot be) started every function degrades to
 * a no-op, so canyon keeps its classic log-to-stderr behaviour.
 *
 * License: MIT. See the LICENSE file for details.
 */

#ifndef CANYON_TUI_H
#define CANYON_TUI_H

#include "canyon.h"

/*
 * Start the ncurses UI (spawns the UI thread; all curses calls happen
 * there). mode is a short description of the session (e.g. "TCP/TLS")
 * shown in the title bar.
 * Returns 0 on success; -1 when there is no usable terminal, in which
 * case canyon should continue in classic log mode (see tui_error()).
 */
int tui_init(const char *mode);

/* Stop the UI thread and restore the terminal. Safe to call even when
 * tui_init() was never called or failed. */
void tui_shutdown(void);

/* True while the ncurses UI is running. */
bool tui_active(void);

/* Human-readable reason for the last tui_init() failure. */
const char *tui_error(void);

/* Data feeds (thread-safe; no-ops when the UI is not active). */
void tui_stream(const void *data, size_t n);   /* TCP stream / WS payload */
void tui_datagram(const void *data, size_t n); /* one UDP datagram */
void tui_event(const char *type, const char *msg);

/* Session state and counters shown in the status bars. */
void tui_set_state(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void tui_stat_sent(unsigned long chunks, unsigned long long bytes);

/* True while the user paused sending with 'p'. */
bool tui_paused(void);

#endif /* CANYON_TUI_H */
