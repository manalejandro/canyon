/*
 * ws.c - WebSocket (RFC 6455) client support for canyon
 */

#include "canyon.h"
#include "rand.h"
#include "tls.h"
#include "ws.h"

#include <strings.h>

#define WS_MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* ------------------------------------------------------------------ */
/* SHA-1 (RFC 3174)                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[5];
    uint64_t len;
    uint8_t block[64];
    size_t used;
} sha1_ctx;

static uint32_t rol32(uint32_t v, int b)
{
    return (v << b) | (v >> (32 - b));
}

static void sha1_block(sha1_ctx *c, const uint8_t *p)
{
    uint32_t w[80];
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 80; i++)
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4];
    for (i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & cc) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ cc ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & cc) | (b & d) | (cc & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ cc ^ d;
            k = 0xCA62C1D6u;
        }
        uint32_t t = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = cc;
        cc = rol32(b, 30);
        b = a;
        a = t;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
}

static void sha1_init(sha1_ctx *c)
{
    c->h[0] = 0x67452301u;
    c->h[1] = 0xEFCDAB89u;
    c->h[2] = 0x98BADCFEu;
    c->h[3] = 0x10325476u;
    c->h[4] = 0xC3D2E1F0u;
    c->len = 0;
    c->used = 0;
}

static void sha1_update(sha1_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = data;

    c->len += n;
    while (n > 0) {
        size_t need = 64 - c->used;
        size_t take = n < need ? n : need;
        memcpy(c->block + c->used, p, take);
        c->used += take;
        p += take;
        n -= take;
        if (c->used == 64) {
            sha1_block(c, c->block);
            c->used = 0;
        }
    }
}

static void sha1_final(sha1_ctx *c, uint8_t out[20])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    uint8_t zero = 0;
    uint8_t lb[8];
    int i;

    sha1_update(c, &pad, 1);
    while (c->used != 56)
        sha1_update(c, &zero, 1);
    for (i = 0; i < 8; i++)
        lb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha1_update(c, lb, 8);

    for (i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Base64 encoding                                                     */
/* ------------------------------------------------------------------ */

static void b64_encode(const uint8_t *in, size_t n, char *out)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;

    while (i + 3 <= n) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                     (uint32_t)in[i + 2];
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];
        out[o++] = tbl[v & 63];
        i += 3;
    }
    size_t rem = n - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = '\0';
}

/* ------------------------------------------------------------------ */
/* Handshake                                                           */
/* ------------------------------------------------------------------ */

int ws_handshake(conn_t *conn, const char *hostname, int port,
                 const char *path, uint8_t key16[16],
                 uint8_t *spill, size_t *spill_len, size_t spill_cap,
                 char *err, size_t errlen)
{
    char keyb64[33];
    char req[1024];
    int len;

    b64_encode(key16, 16, keyb64);

    len = snprintf(req, sizeof req,
                   "GET %s HTTP/1.1\r\n"
                   "Host: %s:%d\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "User-Agent: canyon/%s\r\n"
                   "\r\n",
                   path, hostname, port, keyb64, CANYON_VERSION);
    if (len <= 0 || (size_t)len >= sizeof req) {
        snprintf(err, errlen, "ws: request too long");
        return -1;
    }
    if (conn_send_all(conn, req, (size_t)len) < 0) {
        snprintf(err, errlen, "ws: sending upgrade request failed: %s",
                 strerror(errno));
        return -1;
    }

    uint8_t resp[16384];
    size_t rlen = 0;
    for (;;) {
        ssize_t r = conn_recv(conn, resp + rlen, sizeof resp - rlen - 1);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            snprintf(err, errlen, "ws: no upgrade response: %s",
                     r < 0 ? strerror(errno) : "connection closed");
            return -1;
        }
        rlen += (size_t)r;
        resp[rlen] = '\0';
        if (strstr((char *)resp, "\r\n\r\n"))
            break;
        if (rlen + 1 >= sizeof resp) {
            snprintf(err, errlen, "ws: upgrade response too large");
            return -1;
        }
    }

    if (strncmp((char *)resp, "HTTP/1.1 101", 12) != 0 &&
        strncmp((char *)resp, "HTTP/1.0 101", 12) != 0) {
        size_t el = strcspn((char *)resp, "\r\n");
        char line[128];
        snprintf(line, sizeof line, "%.*s",
                 (int)(el < sizeof line - 1 ? el : sizeof line - 1),
                 (char *)resp);
        snprintf(err, errlen, "ws: upgrade rejected: %s", line);
        return -1;
    }

    sha1_ctx sc;
    uint8_t digest[20];
    char expect[29];
    sha1_init(&sc);
    /* RFC 6455: accept = base64(SHA1(Sec-WebSocket-Key-string + GUID)) */
    sha1_update(&sc, keyb64, strlen(keyb64));
    sha1_update(&sc, WS_MAGIC, sizeof WS_MAGIC - 1);
    sha1_final(&sc, digest);
    b64_encode(digest, 20, expect);

    char accept[64] = "";
    char *copy = strdup((char *)resp);
    if (copy) {
        char *save = NULL;
        char *line = strtok_r(copy, "\r\n", &save);
        while (line) {
            if (strncasecmp(line, "Sec-WebSocket-Accept:", 21) == 0) {
                const char *v = line + 21;
                while (*v == ' ')
                    v++;
                snprintf(accept, sizeof accept, "%s", v);
                break;
            }
            line = strtok_r(NULL, "\r\n", &save);
        }
        free(copy);
    }

    if (accept[0] && strcmp(accept, expect) != 0) {
        snprintf(err, errlen, "ws: Sec-WebSocket-Accept mismatch (got '%s')",
                 accept);
        return -1;
    }

    /* hand the bytes after the response headers back to the caller */
    *spill_len = 0;
    const char *end = strstr((char *)resp, "\r\n\r\n");
    if (end) {
        size_t consumed = (size_t)(end + 4 - (char *)resp);
        if (rlen > consumed) {
            size_t left = rlen - consumed;
            size_t take = left < spill_cap ? left : spill_cap;
            memcpy(spill, resp + consumed, take);
            *spill_len = take;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Frame building (client -> server, must be masked)                   */
/* ------------------------------------------------------------------ */

ssize_t ws_build_frame(uint8_t *out, size_t outcap, uint8_t opcode,
                       const void *payload, size_t plen)
{
    size_t hlen = 2;

    if (plen > 0xffff)
        hlen = 10;
    else if (plen >= 126)
        hlen = 4;

    size_t need = hlen + 4 + plen;      /* header + mask + payload */
    if (need > outcap)
        return -1;

    out[0] = 0x80 | (opcode & 0x0f);
    if (plen <= 125) {
        out[1] = 0x80 | (uint8_t)plen;
    } else if (plen <= 0xffff) {
        out[1] = 0x80 | 126;
        out[2] = (uint8_t)(plen >> 8);
        out[3] = (uint8_t)(plen & 0xff);
    } else {
        out[1] = 0x80 | 127;
        uint64_t p = plen;
        for (int i = 0; i < 8; i++)
            out[2 + i] = (uint8_t)(p >> (56 - 8 * i));
    }

    uint32_t k = (uint32_t)rand_uint64();
    if (k == 0)
        k = 1;
    uint8_t mask[4] = { (uint8_t)k, (uint8_t)(k >> 8),
                        (uint8_t)(k >> 16), (uint8_t)(k >> 24) };
    memcpy(out + hlen, mask, 4);

    const uint8_t *p = payload;
    uint8_t *d = out + hlen + 4;
    for (size_t i = 0; i < plen; i++)
        d[i] = p[i] ^ mask[i & 3];

    return (ssize_t)need;
}

/* ------------------------------------------------------------------ */
/* Frame parsing (server -> client)                                    */
/* ------------------------------------------------------------------ */

int ws_parse_frame(const uint8_t *buf, size_t n, ws_frame_t *f)
{
    memset(f, 0, sizeof *f);
    if (n < 2)
        return 0;

    uint8_t b0 = buf[0], b1 = buf[1];
    if (b0 & 0x70)                  /* RSV bits must be 0 */
        return -1;

    f->fin = (b0 & 0x80) != 0;
    f->opcode = b0 & 0x0f;
    f->masked = (b1 & 0x80) != 0;

    uint64_t len = b1 & 0x7f;
    size_t hlen = 2;
    if (len == 126) {
        if (n < 4)
            return 0;
        len = ((uint64_t)buf[2] << 8) | buf[3];
        hlen = 4;
    } else if (len == 127) {
        if (n < 10)
            return 0;
        len = 0;
        for (int i = 0; i < 8; i++)
            len = (len << 8) | buf[2 + i];
        hlen = 10;
    }
    if (f->masked)
        hlen += 4;

    if (n < hlen)
        return 0;

    f->header_len = hlen;
    f->plen = (size_t)len;
    f->frame_len = hlen + (size_t)len;
    f->payload = buf + hlen;
    if (f->masked)
        memcpy(f->mask, buf + hlen - 4, 4);

    if (n < f->frame_len)
        return 0;
    return 1;
}