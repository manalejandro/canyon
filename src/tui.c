/*
 * tui.c - interactive ncurses interface for canyon
 *
 * All ncurses calls happen on a dedicated UI thread; the sender and
 * receiver threads only append into bounded, mutex-protected ring
 * buffers (1 MiB of received bytes + 1024 event lines). The screen is
 * repainted at most every REDRAW_MS milliseconds, so a full-speed flood
 * never turns into screen spam: only the latest data is shown, while
 * everything is still persisted to disk by the logbook as usual.
 *
 * License: MIT. See the LICENSE file for details.
 */

#include "canyon.h"
#include "tui.h"

#ifdef CANYON_NO_TUI

/* ------------------------- stubbed-out TUI -------------------------- */

int tui_init(const char *mode)
{
    (void)mode;
    return -1;
}

void tui_shutdown(void)
{
}

bool tui_active(void)
{
    return false;
}

const char *tui_error(void)
{
    return "built without ncurses support";
}

void tui_stream(const void *data, size_t n)
{
    (void)data;
    (void)n;
}

void tui_datagram(const void *data, size_t n)
{
    (void)data;
    (void)n;
}

void tui_event(const char *type, const char *msg)
{
    (void)type;
    (void)msg;
}

void tui_set_state(const char *fmt, ...)
{
    (void)fmt;
}

void tui_stat_sent(unsigned long chunks, unsigned long long bytes)
{
    (void)chunks;
    (void)bytes;
}

bool tui_paused(void)
{
    return false;
}

#else /* !CANYON_NO_TUI */

#include <ncurses.h>
#include <term.h>       /* setupterm() */

#include <locale.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <sys/time.h>

/* ----------------------------- tuning ------------------------------- */

#define DATA_RING     (1u << 20)  /* received bytes kept on screen */
#define EV_RING       1024        /* event lines kept */
#define EV_LINE       400         /* max stored event line length */
#define REDRAW_MS     80          /* input poll + min redraw interval */
#define HEX_LINEW     96          /* scratch width of a hexdump line */
#define TEXT_UNIT_MAX 2048        /* max width of a text-mode line */
#define MIN_COLS      48
#define MIN_LINES     10

/* ----------------------- shared state (mutex) ----------------------- */

static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;

static uint8_t *g_ring;             /* circular buffer, DATA_RING bytes */
static size_t g_ring_len;           /* valid bytes: [total-len, total) */
static uint64_t g_total_recv;       /* absolute received byte count */
static unsigned long long g_recv_msgs;

static char g_ev_lines[EV_RING][EV_LINE];
static unsigned char g_ev_colors[EV_RING];
static size_t g_ev_head;            /* next write slot */
static size_t g_ev_count;

static char g_state[128];
static unsigned long g_sent_chunks;
static unsigned long long g_sent_bytes;

static char g_mode[96] = "raw";
static char g_err[160] = "not initialized";

/* --------------------------- UI thread state ------------------------ */

enum { VIEW_HEX = 0, VIEW_TEXT = 1 };

static atomic_bool g_ui_run;
static atomic_bool g_tui_active;
static atomic_bool g_paused;
static atomic_int g_init_done;
static atomic_int g_init_rc;

static pthread_t g_tid;
static bool g_thread_started;
static uint64_t g_start_ms;

static int g_view = VIEW_HEX;
static bool g_follow = true;        /* data pane tracks the tail */
static uint64_t g_view_end;         /* absolute offset at the view bottom */
static int g_ev_scroll;             /* event lines back from the tail */
static int g_focus;                 /* 0 = data pane, 1 = events */

static WINDOW *g_wdata, *g_wev;
static int g_geo_h = -1, g_geo_w = -1;
static int g_data_y, g_data_h, g_ev_y, g_ev_h;

static char *g_scratch;             /* rendered data lines */
static size_t g_scratch_sz;
static size_t g_stride;             /* bytes per scratch line */

/* rate estimation (UI thread only) */
static double g_rate_sent, g_rate_recv;
static uint64_t g_rs_t;
static unsigned long long g_rs_sent, g_rs_recv;

/* color pairs */
enum {
    C_STAT = 1, C_PANE, C_PANE_ACT, C_GUTTER,
    C_ERR, C_WARN, C_OK, C_NOTE
};
static bool g_color;

#define CP(n) (g_color ? COLOR_PAIR(n) : A_NORMAL)

/* ------------------------------ helpers ----------------------------- */

static void set_err(const char *s)
{
    snprintf(g_err, sizeof g_err, "%s", s);
}

static void time_str(char *out, size_t n)
{
    struct timeval tv;
    struct tm tmv;
    char base[16];

    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tmv);
    strftime(base, sizeof base, "%H:%M:%S", &tmv);
    snprintf(out, n, "%s.%03d", base, (int)(tv.tv_usec / 1000));
}

static void fmt_bytes(double v, char *out, size_t n)
{
    if (v < 1000.0)
        snprintf(out, n, "%.0f B", v);
    else if (v < 1e6)
        snprintf(out, n, "%.1f KiB", v / 1024.0);
    else if (v < 1e9)
        snprintf(out, n, "%.2f MiB", v / (1024.0 * 1024.0));
    else
        snprintf(out, n, "%.2f GiB", v / (1024.0 * 1024.0 * 1024.0));
}

static void fmt_uptime(uint64_t ms, char *out, size_t n)
{
    uint64_t s = ms / 1000;

    if (s < 60)
        snprintf(out, n, "%llus", (unsigned long long)s);
    else if (s < 3600)
        snprintf(out, n, "%llum%02llus", (unsigned long long)(s / 60),
                 (unsigned long long)(s % 60));
    else
        snprintf(out, n, "%lluh%02llum", (unsigned long long)(s / 3600),
                 (unsigned long long)((s % 3600) / 60));
}

/* Print at most len bytes of s at (y,x) inside w, clipped to the window,
 * never wrapping into the border. */
static void wseg(WINDOW *w, int y, int x, const char *s, int len, attr_t attr)
{
    int maxx = getmaxx(w) - 1;

    if (y < 0 || y >= getmaxy(w) || x >= maxx || len <= 0)
        return;
    if (x + len > maxx)
        len = maxx - x;
    wattrset(w, attr);
    mvwprintw(w, y, x, "%.*s", len, s);
}

/* Full-width attribute bar on stdscr (title / stats / help rows). */
static char g_barbuf[8192];

static void bar(int y, const char *s, attr_t attr)
{
    int w = COLS;
    size_t len;

    if (w < 1 || y < 0 || y >= LINES)
        return;
    snprintf(g_barbuf, sizeof g_barbuf, "%s", s);
    len = strlen(g_barbuf);
    while ((int)len < w && len + 1 < sizeof g_barbuf)
        g_barbuf[len++] = ' ';
    g_barbuf[len] = '\0';
    attrset(attr);
    mvprintw(y, 0, "%.*s", w, g_barbuf);
    attrset(A_NORMAL);
}

/* --------------------------- ring buffers --------------------------- */

/* All ring functions are called with g_mtx held. */

static void ring_append(const void *data, size_t n)
{
    const uint8_t *p = data;
    uint64_t start_abs = g_total_recv;
    uint64_t oldest = g_total_recv - g_ring_len;
    size_t pos, first;

    if (n >= DATA_RING) {           /* keep only the tail of a huge read */
        uint64_t dropped = (uint64_t)n - DATA_RING;
        p += dropped;
        n = DATA_RING;
        start_abs += dropped;
    }

    pos = (size_t)(start_abs % DATA_RING);
    first = DATA_RING - pos;
    if (first > n)
        first = n;
    memcpy(g_ring + pos, p, first);
    if (n > first)
        memcpy(g_ring, p + first, n - first);

    g_total_recv = start_abs + n;
    if (g_total_recv - oldest > DATA_RING)
        oldest = g_total_recv - DATA_RING;
    g_ring_len = (size_t)(g_total_recv - oldest);
}

static void ring_read(uint64_t off, void *dst, size_t n)
{
    size_t pos = (size_t)(off % DATA_RING);
    size_t first = DATA_RING - pos;

    if (first > n)
        first = n;
    memcpy(dst, g_ring + pos, first);
    if (n > first)
        memcpy(dst, g_ring, n - first);
}

static unsigned char ev_color(const char *type)
{
    if (strstr(type, "error"))
        return C_ERR;
    if (!strcmp(type, "disconnect") || !strcmp(type, "random_eof") ||
        !strcmp(type, "random_short") || !strcmp(type, "ws_close") ||
        !strcmp(type, "ws_skip"))
        return C_WARN;
    if (!strcmp(type, "connect") || !strcmp(type, "end"))
        return C_OK;
    if (!strcmp(type, "ui") || !strcmp(type, "log"))
        return C_NOTE;
    return 0;
}

static void ev_append(unsigned char col, const char *line)
{
    size_t i = g_ev_head;

    snprintf(g_ev_lines[i], EV_LINE, "%s", line);
    g_ev_colors[i] = col;
    g_ev_head = (i + 1) % EV_RING;
    if (g_ev_count < EV_RING)
        g_ev_count++;
}

/* ------------------------------ public feeds ------------------------ */

void tui_stream(const void *data, size_t n)
{
    if (!atomic_load_explicit(&g_tui_active, memory_order_relaxed) || n == 0)
        return;
    pthread_mutex_lock(&g_mtx);
    ring_append(data, n);
    g_recv_msgs++;
    pthread_mutex_unlock(&g_mtx);
}

void tui_datagram(const void *data, size_t n)
{
    if (!atomic_load_explicit(&g_tui_active, memory_order_relaxed) || n == 0)
        return;
    pthread_mutex_lock(&g_mtx);
    ring_append(data, n);
    g_recv_msgs++;
    pthread_mutex_unlock(&g_mtx);
}

void tui_event(const char *type, const char *msg)
{
    char ts[32];
    char line[EV_LINE];

    if (!atomic_load_explicit(&g_tui_active, memory_order_relaxed))
        return;
    time_str(ts, sizeof ts);
    snprintf(line, sizeof line, "%s %-13s %s", ts, type ? type : "?",
             msg ? msg : "");
    pthread_mutex_lock(&g_mtx);
    ev_append(ev_color(type ? type : ""), line);
    pthread_mutex_unlock(&g_mtx);
}

void tui_set_state(const char *fmt, ...)
{
    char s[sizeof g_state];
    va_list ap;

    if (!atomic_load_explicit(&g_tui_active, memory_order_relaxed))
        return;
    va_start(ap, fmt);
    vsnprintf(s, sizeof s, fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&g_mtx);
    snprintf(g_state, sizeof g_state, "%s", s);
    pthread_mutex_unlock(&g_mtx);
}

void tui_stat_sent(unsigned long chunks, unsigned long long bytes)
{
    if (!atomic_load_explicit(&g_tui_active, memory_order_relaxed))
        return;
    pthread_mutex_lock(&g_mtx);
    g_sent_chunks = chunks;
    g_sent_bytes = bytes;
    pthread_mutex_unlock(&g_mtx);
}

bool tui_paused(void)
{
    return atomic_load_explicit(&g_paused, memory_order_relaxed);
}

bool tui_active(void)
{
    return atomic_load_explicit(&g_tui_active, memory_order_relaxed);
}

const char *tui_error(void)
{
    return g_err;
}

/* ------------------------------ rendering --------------------------- */

static void relayout(void)
{
    int H = LINES, W = COLS;
    int mid, ev_h, data_h, rows, cw;
    size_t need;

    if (g_wdata && H == g_geo_h && W == g_geo_w)
        return;
    if (g_wdata) {
        delwin(g_wdata);
        g_wdata = NULL;
    }
    if (g_wev) {
        delwin(g_wev);
        g_wev = NULL;
    }

    mid = H - 3;                    /* title + stats + help rows */
    if (mid < 2)
        mid = 2;
    ev_h = mid / 3;
    if (ev_h < 3)
        ev_h = (mid >= 4) ? 3 : mid - 1;
    if (ev_h > mid - 1)
        ev_h = mid - 1;
    data_h = mid - ev_h;
    if (data_h < 1)
        data_h = 1;

    g_data_y = 2;
    g_data_h = data_h;
    g_ev_y = 2 + data_h;
    g_ev_h = ev_h;
    g_geo_h = H;
    g_geo_w = W;

    g_wdata = newwin(data_h, W, 2, 0);
    g_wev = newwin(ev_h, W, 2 + data_h, 0);

    rows = data_h - 2;
    if (rows < 1)
        rows = 1;
    cw = W - 2;
    if (cw < 80)
        cw = 80;
    if (cw > TEXT_UNIT_MAX)
        cw = TEXT_UNIT_MAX;
    g_stride = (size_t)cw + 16;
    need = (size_t)rows * g_stride;
    if (need > g_scratch_sz) {
        char *ns = realloc(g_scratch, need);
        if (ns) {
            g_scratch = ns;
            g_scratch_sz = need;
        }
    }
}

static void pane_frame(WINDOW *w, const char *title, bool focused)
{
    attr_t attr = CP(focused ? C_PANE_ACT : C_PANE);

    werase(w);
    wattrset(w, attr);
    box(w, 0, 0);
    wseg(w, 0, 2, title, (int)strlen(title), attr | A_BOLD);
    wattrset(w, A_NORMAL);
}

/* Format one hexdump line into out (fixed 79 chars + NUL):
 *   OOOOOOOO  hh hh hh hh hh hh hh hh  hh hh hh hh hh hh hh hh  |ascii..........|
 * lead = bytes missing before the first available one, have = bytes in b. */
static void fmt_hex_line(char *out, uint64_t off, const uint8_t *b,
                         size_t lead, size_t have)
{
    int n = 0;
    int i;

    n += sprintf(out + n, "%08llx  ",
                 (unsigned long long)(off & 0xffffffffu));
    for (i = 0; i < 16; i++) {
        if (i == 8)
            out[n++] = ' ';
        if ((size_t)i < lead || (size_t)i >= lead + have)
            n += sprintf(out + n, "   ");
        else
            n += sprintf(out + n, "%02x ", b[i - lead]);
    }
    n += sprintf(out + n, "  |");
    for (i = 0; i < 16; i++) {
        if ((size_t)i < lead || (size_t)i >= lead + have) {
            out[n++] = ' ';
        } else {
            uint8_t c = b[i - lead];
            out[n++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
    }
    out[n++] = '|';
    out[n] = '\0';
}

static void fmt_text_line(char *out, const uint8_t *b, size_t lead,
                          size_t have, int width)
{
    int n = 0;
    int i;

    for (i = 0; i < width; i++) {
        if ((size_t)i < lead || (size_t)i >= lead + have) {
            out[n++] = ' ';
        } else {
            uint8_t c = b[i - lead];
            out[n++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
    }
    out[n] = '\0';
}

static void draw_data(void)
{
    int rows = g_data_h - 2;
    int cols = COLS - 2;
    int tcols;
    uint64_t unit, span, start, end, end_al, total, oldest;
    unsigned long long msgs;
    size_t linew;
    char title[256];
    int rendered = 0;
    int r;

    if (rows < 1)
        rows = 1;
    if (cols < 8)
        cols = 8;
    tcols = cols > TEXT_UNIT_MAX ? TEXT_UNIT_MAX : cols;

    pthread_mutex_lock(&g_mtx);
    total = g_total_recv;
    oldest = total - g_ring_len;
    msgs = g_recv_msgs;
    if (g_follow)
        g_view_end = total;
    if (g_view_end > total)
        g_view_end = total;
    end = g_view_end;

    if (g_follow)
        snprintf(title, sizeof title,
                 "received | %s | live | %llu B in %llu msg",
                 g_view == VIEW_HEX ? "hex" : "text",
                 (unsigned long long)total, msgs);
    else {
        char bb[32];
        fmt_bytes((double)(total - end), bb, sizeof bb);
        snprintf(title, sizeof title,
                 "received | %s | -%s behind | %llu B in %llu msg",
                 g_view == VIEW_HEX ? "hex" : "text", bb,
                 (unsigned long long)total, msgs);
    }
    pane_frame(g_wdata, title, g_focus == 0);

    if (total == 0) {
        pthread_mutex_unlock(&g_mtx);
        wattrset(g_wdata, A_DIM);
        mvwprintw(g_wdata, 1, 2, "waiting for data from %s:%d ...",
                  opts.host, opts.port);
        wattrset(g_wdata, A_NORMAL);
        return;
    }
    if (!g_scratch || g_stride < HEX_LINEW) {
        pthread_mutex_unlock(&g_mtx);
        wattrset(g_wdata, A_DIM);
        mvwprintw(g_wdata, 1, 2, "out of memory");
        wattrset(g_wdata, A_NORMAL);
        return;
    }

    if (g_view == VIEW_HEX) {
        unit = 16;
        linew = HEX_LINEW;
        end_al = (end + 15) & ~(uint64_t)15;
        span = unit * (uint64_t)rows;
        start = end_al > span ? end_al - span : 0;
        start &= ~(uint64_t)15;
    } else {
        unit = (uint64_t)tcols;
        linew = (size_t)tcols + 1;
        span = unit * (uint64_t)rows;
        start = end > span ? end - span : 0;
        if (start < oldest)
            start = oldest;
        end_al = end;
    }

    if (linew > g_stride)
        linew = g_stride;

    for (r = 0; r < rows; r++) {
        uint64_t off = start + (uint64_t)r * unit;
        uint64_t lo, hi;
        uint8_t tmp[TEXT_UNIT_MAX];
        size_t have = 0, lead;
        char *ln = g_scratch + (size_t)r * g_stride;

        if (off >= end_al && off >= total)
            break;
        lo = off > oldest ? off : oldest;
        hi = off + unit;
        if (g_view == VIEW_TEXT && hi > end)
            hi = end;
        if (hi > total)
            hi = total;
        if (hi > lo) {
            have = (size_t)(hi - lo);
            ring_read(lo, tmp, have);
        }
        lead = (size_t)(lo - off);
        if (g_view == VIEW_HEX)
            fmt_hex_line(ln, off, tmp, lead, have);
        else
            fmt_text_line(ln, tmp, lead, have, (int)unit);
        rendered++;
    }
    pthread_mutex_unlock(&g_mtx);

    for (r = 0; r < rendered; r++) {
        char *ln = g_scratch + (size_t)r * g_stride;

        if (g_view == VIEW_HEX) {
            /* segments: offset [0,10) hex [10,59) gutter [59,79) */
            wseg(g_wdata, r + 1, 1, ln, 10, A_DIM);
            wseg(g_wdata, r + 1, 11, ln + 10, 49, A_NORMAL);
            wseg(g_wdata, r + 1, 60, ln + 59, 20, CP(C_GUTTER));
        } else {
            wseg(g_wdata, r + 1, 1, ln, (int)linew - 1, A_NORMAL);
        }
    }
}

static void draw_events(void)
{
    int rows = g_ev_h - 2;
    size_t count;
    int show, i;
    char title[128];

    if (rows < 1)
        rows = 1;

    pthread_mutex_lock(&g_mtx);
    count = g_ev_count;
    if (g_ev_scroll > 0 && (size_t)g_ev_scroll >= count)
        g_ev_scroll = count ? (int)count - 1 : 0;
    if (g_ev_scroll > 0)
        snprintf(title, sizeof title, "events | -%d lines", g_ev_scroll);
    else
        snprintf(title, sizeof title, "events | live");
    pane_frame(g_wev, title, g_focus == 1);

    if (count == 0) {
        pthread_mutex_unlock(&g_mtx);
        wattrset(g_wev, A_DIM);
        mvwprintw(g_wev, 1, 2, "no events yet");
        wattrset(g_wev, A_NORMAL);
        return;
    }

    show = (int)count - g_ev_scroll;
    if (show > rows)
        show = rows;
    for (i = 0; i < show; i++) {
        int from_newest = g_ev_scroll + (show - 1 - i);
        size_t idx = (g_ev_head + EV_RING - 1 -
                      (size_t)from_newest % EV_RING) % EV_RING;
        attr_t attr = g_ev_colors[idx] ? CP(g_ev_colors[idx]) : A_NORMAL;

        wseg(g_wev, rows - show + 1 + i, 1, g_ev_lines[idx], EV_LINE, attr);
    }
    pthread_mutex_unlock(&g_mtx);
}

static void sample_rates(void)
{
    uint64_t now = now_ms();
    unsigned long long sb, rb;

    pthread_mutex_lock(&g_mtx);
    sb = g_sent_bytes;
    rb = g_total_recv;
    pthread_mutex_unlock(&g_mtx);

    if (g_rs_t == 0) {
        g_rs_t = now;
        g_rs_sent = sb;
        g_rs_recv = rb;
        return;
    }
    if (now - g_rs_t >= 250) {
        double dt = (double)(now - g_rs_t) / 1000.0;
        double is = (double)(sb - g_rs_sent) / dt;
        double ir = (double)(rb - g_rs_recv) / dt;

        g_rate_sent += (is - g_rate_sent) * 0.4;
        g_rate_recv += (ir - g_rate_recv) * 0.4;
        g_rs_t = now;
        g_rs_sent = sb;
        g_rs_recv = rb;
    }
}

static void draw_title(void)
{
    char state[sizeof g_state];
    char t[512];

    pthread_mutex_lock(&g_mtx);
    snprintf(state, sizeof state, "%s", g_state);
    pthread_mutex_unlock(&g_mtx);

    snprintf(t, sizeof t, " canyon %s | target %s:%d | %s | %s ",
             CANYON_VERSION, opts.host, opts.port, g_mode,
             state[0] ? state : "starting");
    bar(0, t, A_REVERSE | A_BOLD);

    if (atomic_load(&g_paused)) {
        const char *p = " PAUSED ";
        int x = COLS - (int)strlen(p);

        if (x < 0)
            x = 0;
        attrset(A_REVERSE | A_BOLD | CP(C_WARN));
        mvprintw(0, x, "%s", p);
        attrset(A_NORMAL);
    }
}

static void draw_stats(void)
{
    char up[24], sb[32], rb[32], sr[32], rr[32], t[1024];
    unsigned long sc;
    unsigned long long sbytes, rmsgs, rbytes;

    pthread_mutex_lock(&g_mtx);
    sc = g_sent_chunks;
    sbytes = g_sent_bytes;
    rmsgs = g_recv_msgs;
    rbytes = g_total_recv;
    pthread_mutex_unlock(&g_mtx);

    fmt_uptime(now_ms() - g_start_ms, up, sizeof up);
    fmt_bytes((double)sbytes, sb, sizeof sb);
    fmt_bytes((double)rbytes, rb, sizeof rb);
    fmt_bytes(g_rate_sent, sr, sizeof sr);
    fmt_bytes(g_rate_recv, rr, sizeof rr);

    snprintf(t, sizeof t,
             " up %s | sent %lu ch / %s (%s/s) | recv %llu msg / %s (%s/s)"
             " | src %s | logs %s ",
             up, sc, sb, sr, rmsgs, rb, rr,
             opts.random_source, opts.outdir);
    bar(1, t, CP(C_STAT));
}

static void draw_help(void)
{
    bar(LINES - 1,
        " q quit | p pause | x hex/text | c clear | tab focus | "
        "arrows/pgup/pgdn scroll | home oldest | end live | ctrl-l redraw ",
        A_REVERSE);
}

static void draw_all(void)
{
    relayout();
    if (!g_wdata || !g_wev)
        return;
    sample_rates();
    werase(stdscr);
    draw_title();
    draw_stats();
    draw_data();
    draw_events();
    draw_help();
    /* stdscr first: it covers the whole screen, the panes overlay their
     * regions on the virtual screen afterwards. */
    wnoutrefresh(stdscr);
    wnoutrefresh(g_wdata);
    wnoutrefresh(g_wev);
    doupdate();
}

/* ------------------------------ scrolling --------------------------- */

static int page_rows(void)
{
    int rows = (g_focus == 0 ? g_data_h : g_ev_h) - 2;

    return rows < 1 ? 1 : rows;
}

static void data_scroll(int nlines)
{
    pthread_mutex_lock(&g_mtx);
    uint64_t total = g_total_recv;
    uint64_t oldest = total - g_ring_len;
    int cols = COLS - 2;
    uint64_t unit;

    if (cols < 8)
        cols = 8;
    if (cols > TEXT_UNIT_MAX)
        cols = TEXT_UNIT_MAX;
    unit = (g_view == VIEW_HEX) ? 16 : (uint64_t)cols;

    g_follow = false;
    if (nlines > 0) {
        uint64_t d = unit * (uint64_t)nlines;

        if (total - g_view_end >= d && g_view_end + d <= total)
            g_view_end += d;
        else
            g_view_end = total;
        if (g_view_end >= total)
            g_follow = true;
    } else {
        uint64_t d = unit * (uint64_t)(-(int64_t)nlines);
        uint64_t minv = oldest + unit;

        if (minv > total)
            minv = total;
        g_view_end = (g_view_end > d + minv) ? g_view_end - d : minv;
    }
    pthread_mutex_unlock(&g_mtx);
}

static void data_home(void)
{
    pthread_mutex_lock(&g_mtx);
    uint64_t oldest = g_total_recv - g_ring_len;
    uint64_t minv = oldest + 1;

    if (minv > g_total_recv)
        minv = g_total_recv;
    g_view_end = minv;
    g_follow = (minv >= g_total_recv);
    pthread_mutex_unlock(&g_mtx);
}

static void data_end(void)
{
    pthread_mutex_lock(&g_mtx);
    g_view_end = g_total_recv;
    g_follow = true;
    pthread_mutex_unlock(&g_mtx);
}

static void ev_scroll_by(int nlines)
{
    pthread_mutex_lock(&g_mtx);
    int maxs = g_ev_count ? (int)g_ev_count - 1 : 0;

    g_ev_scroll -= nlines;          /* nlines > 0 = towards newer */
    if (g_ev_scroll < 0)
        g_ev_scroll = 0;
    if (g_ev_scroll > maxs)
        g_ev_scroll = maxs;
    pthread_mutex_unlock(&g_mtx);
}

static void do_scroll(int nlines)
{
    if (g_focus == 0)
        data_scroll(nlines);
    else
        ev_scroll_by(nlines);
}

/* ------------------------------- actions ---------------------------- */

static void tui_clear(void)
{
    pthread_mutex_lock(&g_mtx);
    g_ring_len = 0;                 /* forget scrollback, keep counters */
    g_ev_count = 0;
    g_ev_head = 0;
    g_view_end = g_total_recv;
    g_follow = true;
    g_ev_scroll = 0;
    pthread_mutex_unlock(&g_mtx);
    tui_event("ui", "screen cleared (counters and disk logs kept)");
}

static void handle_key(int ch)
{
    switch (ch) {
    case 'q':
    case 'Q':
        pthread_mutex_lock(&g_mtx);
        snprintf(g_state, sizeof g_state, "stopping...");
        pthread_mutex_unlock(&g_mtx);
        tui_event("ui", "quit requested");
        canyon_stop();
        break;
    case 'p':
    case 'P': {
        bool np = !atomic_load(&g_paused);

        atomic_store(&g_paused, np);
        tui_event("ui", np ? "sending paused" : "sending resumed");
        break;
    }
    case 'x':
    case 'X':
        g_view = (g_view == VIEW_HEX) ? VIEW_TEXT : VIEW_HEX;
        break;
    case 'c':
    case 'C':
        tui_clear();
        break;
    case '\t':
    case KEY_BTAB:
        g_focus ^= 1;
        break;
    case KEY_UP:
        do_scroll(-1);
        break;
    case KEY_DOWN:
        do_scroll(1);
        break;
    case KEY_PPAGE:
        do_scroll(-page_rows());
        break;
    case KEY_NPAGE:
        do_scroll(page_rows());
        break;
    case KEY_HOME:
        if (g_focus == 0)
            data_home();
        else
            ev_scroll_by(1 << 30);
        break;
    case KEY_END:
        if (g_focus == 0)
            data_end();
        else
            ev_scroll_by(-(1 << 30));
        break;
    case 12:                        /* Ctrl-L */
    case KEY_CLEAR:
        wclear(stdscr);
        if (g_wdata)
            wclear(g_wdata);
        if (g_wev)
            wclear(g_wev);
        draw_all();
        break;
    default:
        break;
    }
}

static void handle_mouse(void)
{
    MEVENT me;

    if (getmouse(&me) != OK)
        return;
    if (me.bstate & (BUTTON1_PRESSED | BUTTON1_CLICKED)) {
        if (me.y >= g_data_y && me.y < g_data_y + g_data_h)
            g_focus = 0;
        else if (me.y >= g_ev_y && me.y < g_ev_y + g_ev_h)
            g_focus = 1;
    }
    if (me.bstate & BUTTON4_PRESSED)
        do_scroll(-3);
    else if (me.bstate & BUTTON5_PRESSED)
        do_scroll(3);
#ifdef BUTTON6_PRESSED
    else if (me.bstate & BUTTON6_PRESSED)
        do_scroll(-3);
#endif
#ifdef BUTTON7_PRESSED
    else if (me.bstate & BUTTON7_PRESSED)
        do_scroll(3);
#endif
}

/* ------------------------------ lifecycle --------------------------- */

static int screen_setup(void)
{
    int err = 0;

    if (setupterm(NULL, STDOUT_FILENO, &err) != OK) {
        set_err(err == 0 ? "unknown terminal type"
                         : "cannot access the terminfo database");
        return -1;
    }
    if (initscr() == NULL) {
        set_err("initscr() failed");
        return -1;
    }
    if (LINES < MIN_LINES || COLS < MIN_COLS) {
        endwin();
        set_err("terminal too small (need at least 48x10)");
        return -1;
    }

    cbreak();
    noecho();
    nonl();
    intrflush(stdscr, FALSE);
    keypad(stdscr, TRUE);
    timeout(REDRAW_MS);
    curs_set(0);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(C_STAT, COLOR_CYAN, -1);
        init_pair(C_PANE, COLOR_CYAN, -1);
        init_pair(C_PANE_ACT, COLOR_YELLOW, -1);
        init_pair(C_GUTTER, COLOR_GREEN, -1);
        init_pair(C_ERR, COLOR_RED, -1);
        init_pair(C_WARN, COLOR_YELLOW, -1);
        init_pair(C_OK, COLOR_GREEN, -1);
        init_pair(C_NOTE, COLOR_MAGENTA, -1);
        g_color = true;
    }
    mousemask(ALL_MOUSE_EVENTS | REPORT_MOUSE_POSITION, NULL);

    g_start_ms = now_ms();
    atomic_store(&g_tui_active, true);
    return 0;
}

static void *tui_thread(void *unused)
{
    uint64_t last = 0;
    int rc = screen_setup();

    (void)unused;
    atomic_store_explicit(&g_init_rc, rc, memory_order_relaxed);
    atomic_store_explicit(&g_init_done, 1, memory_order_release);
    if (rc != 0)
        return NULL;

    while (atomic_load(&g_ui_run)) {
        int ch = getch();
        uint64_t now;

        if (ch == KEY_MOUSE)
            handle_mouse();
        else if (ch == KEY_RESIZE) {
            wclear(stdscr);
            draw_all();
            last = now_ms();
            continue;
        } else if (ch != ERR)
            handle_key(ch);

        now = now_ms();
        if (now - last >= REDRAW_MS) {
            draw_all();
            last = now;
        }
    }

    atomic_store(&g_tui_active, false);
    curs_set(1);
    endwin();
    return NULL;
}

int tui_init(const char *mode)
{
    int rc;

    if (mode)
        snprintf(g_mode, sizeof g_mode, "%s", mode);
    if (!isatty(STDOUT_FILENO) || !isatty(STDIN_FILENO)) {
        set_err("stdin/stdout is not a terminal");
        return -1;
    }
    /* Let ncurses(w) draw real UTF-8 box characters when the user's
     * locale supports it; all strings canyon prints are ASCII-only, so
     * this is also safe with the narrow ncurses library. */
    setlocale(LC_ALL, "");
    g_ring = malloc(DATA_RING);
    if (!g_ring) {
        set_err("out of memory");
        return -1;
    }

    atomic_store(&g_ui_run, true);
    atomic_store(&g_init_done, 0);
    atomic_store(&g_init_rc, -1);
    if (pthread_create(&g_tid, NULL, tui_thread, NULL) != 0) {
        free(g_ring);
        g_ring = NULL;
        set_err("cannot create the UI thread");
        return -1;
    }
    g_thread_started = true;

    while (!atomic_load_explicit(&g_init_done, memory_order_acquire))
        sleep_us(1000);
    rc = atomic_load_explicit(&g_init_rc, memory_order_relaxed);
    if (rc != 0) {
        pthread_join(g_tid, NULL);
        g_thread_started = false;
        free(g_ring);
        g_ring = NULL;
    }
    return rc;
}

void tui_shutdown(void)
{
    if (!g_thread_started)
        return;
    atomic_store(&g_ui_run, false);
    pthread_join(g_tid, NULL);
    g_thread_started = false;
    atomic_store(&g_tui_active, false);

    free(g_ring);
    g_ring = NULL;
    free(g_scratch);
    g_scratch = NULL;
    g_scratch_sz = 0;
    if (g_wdata) {
        delwin(g_wdata);
        g_wdata = NULL;
    }
    if (g_wev) {
        delwin(g_wev);
        g_wev = NULL;
    }
    g_geo_h = g_geo_w = -1;
}

#endif /* CANYON_NO_TUI */
