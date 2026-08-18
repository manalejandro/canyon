/*
 * ws.h - WebSocket (RFC 6455) client support for canyon
 *
 * Implements the HTTP Upgrade handshake, client-side frame building
 * (masked binary/text frames) and a streaming parser for incoming frames.
 */

#ifndef CANYON_WS_H
#define CANYON_WS_H

#include "tls.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Maximum frame payload canyon will buffer and log (1 MiB).
 * Larger incoming frames are skipped (their payload is discarded). */
#define WS_MAX_PAYLOAD (1u << 20)

/* Control-frame opcodes */
#define WS_OP_CONT   0x0
#define WS_OP_TEXT   0x1
#define WS_OP_BINARY 0x2
#define WS_OP_CLOSE  0x8
#define WS_OP_PING   0x9
#define WS_OP_PONG   0xA

typedef struct {
    bool fin;
    bool masked;
    uint8_t opcode;
    uint8_t mask[4];
    const uint8_t *payload;   /* valid when the frame is complete */
    size_t plen;
    size_t header_len;        /* 0 until the whole header is buffered */
    size_t frame_len;
} ws_frame_t;

/*
 * Perform the WebSocket upgrade handshake on an already-connected
 * (optionally TLS-wrapped) connection. key16 is the 16-byte random key
 * used to build Sec-WebSocket-Key. hostname is the value used in the
 * Host: header (typically the domain hostname or the target IP).
 *
 * Any bytes received after the end of the HTTP response headers are copied
 * into spill (up to spill_cap) and reported through spill_len, so that the
 * first frame is not lost.
 *
 * Returns 0 on success, -1 on failure (message in err).
 */
int ws_handshake(conn_t *conn, const char *hostname, int port,
                 const char *path, uint8_t key16[16],
                 uint8_t *spill, size_t *spill_len, size_t spill_cap,
                 char *err, size_t errlen);

/*
 * Build a masked client frame (RFC 6455: client frames must be masked).
 * opcode is one of the WS_OP_* constants. Returns the total frame length,
 * or -1 if out is too small.
 */
ssize_t ws_build_frame(uint8_t *out, size_t outcap, uint8_t opcode,
                       const void *payload, size_t plen);

/*
 * Streaming frame parser for incoming data.
 *
 * Given buf[0..n), attempts to parse the next complete frame:
 *   returns  1 on success (ws_frame_t is filled in),
 *   returns  0 if more data is needed (header fields are filled in as far
 *             as determinable; header_len is 0 until the full header is
 *             available),
 *   returns -1 on a protocol error.
 */
int ws_parse_frame(const uint8_t *buf, size_t n, ws_frame_t *f);

#endif /* CANYON_WS_H */