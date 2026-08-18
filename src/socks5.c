/*
 * socks5.c - SOCKS5 proxy handshake (RFC 1928, RFC 1929)
 */

#include "canyon.h"
#include "socks5.h"

#include <arpa/inet.h>
#include <netinet/in.h>

static int s5_recvn(int fd, void *buf, size_t n)
{
    char *p = buf;
    size_t got = 0;

    while (got < n) {
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static int s5_sendn(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    size_t sent = 0;

    while (sent < n) {
        ssize_t r = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}

static int socks5_auth(int fd, const char *user, const char *pass,
                       char *err, size_t errlen)
{
    size_t ulen = strlen(user);
    size_t plen = strlen(pass);
    uint8_t buf[513];
    size_t i = 0;

    if (ulen > 255 || plen > 255) {
        snprintf(err, errlen, "socks5: credentials too long");
        return -1;
    }

    buf[i++] = 0x01;                /* RFC 1929 version */
    buf[i++] = (uint8_t)ulen;
    memcpy(buf + i, user, ulen);
    i += ulen;
    buf[i++] = (uint8_t)plen;
    memcpy(buf + i, pass, plen);
    i += plen;

    if (s5_sendn(fd, buf, i) != 0 || s5_recvn(fd, buf, 2) != 0) {
        snprintf(err, errlen, "socks5: auth exchange failed: %s",
                 strerror(errno));
        return -1;
    }
    if (buf[0] != 0x01 || buf[1] != 0x00) {
        snprintf(err, errlen, "socks5: authentication rejected by proxy");
        return -1;
    }
    return 0;
}

int socks5_handshake(int fd, const char *host, int port,
                     const char *user, const char *pass,
                     char *err, size_t errlen)
{
    bool want_auth = user && *user;
    uint8_t greets[4] = { 5, want_auth ? 2 : 1, 0x00, 0x02 };
    size_t glen = want_auth ? 4 : 3;

    if (s5_sendn(fd, greets, glen) != 0) {
        snprintf(err, errlen, "socks5: greeting failed: %s",
                 strerror(errno));
        return -1;
    }

    uint8_t rep[4];
    if (s5_recvn(fd, rep, 2) != 0) {
        snprintf(err, errlen, "socks5: no greeting response: %s",
                 strerror(errno));
        return -1;
    }
    if (rep[0] != 5) {
        snprintf(err, errlen, "socks5: bad protocol version %u", rep[0]);
        return -1;
    }
    if (rep[1] == 0xFF) {
        snprintf(err, errlen, "socks5: no acceptable authentication method");
        return -1;
    }
    if (rep[1] == 0x02) {
        if (!want_auth) {
            snprintf(err, errlen, "socks5: proxy requires authentication");
            return -1;
        }
        if (socks5_auth(fd, user, pass, err, errlen) != 0)
            return -1;
    } else if (rep[1] != 0x00) {
        snprintf(err, errlen, "socks5: unsupported method %u", rep[1]);
        return -1;
    }

    uint8_t req[264];
    size_t i = 0;
    req[i++] = 5;                   /* VER */
    req[i++] = 1;                   /* CMD: CONNECT */
    req[i++] = 0;                   /* RSV */

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, host, &a4) == 1) {
        req[i++] = 1;               /* ATYP: IPv4 */
        memcpy(req + i, &a4, 4);
        i += 4;
    } else if (inet_pton(AF_INET6, host, &a6) == 1) {
        req[i++] = 4;               /* ATYP: IPv6 */
        memcpy(req + i, &a6, 16);
        i += 16;
    } else {
        size_t hl = strlen(host);
        if (hl > 255) {
            snprintf(err, errlen, "socks5: hostname too long");
            return -1;
        }
        req[i++] = 3;               /* ATYP: domain name */
        req[i++] = (uint8_t)hl;
        memcpy(req + i, host, hl);
        i += hl;
    }
    req[i++] = (uint8_t)(port >> 8);
    req[i++] = (uint8_t)(port & 0xff);

    if (s5_sendn(fd, req, i) != 0) {
        snprintf(err, errlen, "socks5: connect request failed: %s",
                 strerror(errno));
        return -1;
    }

    if (s5_recvn(fd, rep, 4) != 0) {
        snprintf(err, errlen, "socks5: no reply: %s", strerror(errno));
        return -1;
    }
    if (rep[0] != 5) {
        snprintf(err, errlen, "socks5: bad reply version %u", rep[0]);
        return -1;
    }
    if (rep[1] != 0) {
        snprintf(err, errlen, "socks5: connect failed (rep=%u)", rep[1]);
        return -1;
    }

    uint8_t atype = rep[3];
    uint8_t junk[256];
    size_t addrlen;
    switch (atype) {
    case 1:
        addrlen = 4;
        break;
    case 4:
        addrlen = 16;
        break;
    case 3:
        if (s5_recvn(fd, junk, 1) != 0) {
            snprintf(err, errlen, "socks5: truncated reply: %s",
                     strerror(errno));
            return -1;
        }
        addrlen = junk[0];
        break;
    default:
        snprintf(err, errlen, "socks5: bad address type %u", atype);
        return -1;
    }
    if (addrlen > 0 && s5_recvn(fd, junk, addrlen) != 0) {
        snprintf(err, errlen, "socks5: truncated reply address: %s",
                 strerror(errno));
        return -1;
    }
    if (s5_recvn(fd, junk, 2) != 0) {
        snprintf(err, errlen, "socks5: truncated reply port: %s",
                 strerror(errno));
        return -1;
    }
    return 0;
}
