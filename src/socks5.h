/*
 * socks5.h - SOCKS5 proxy handshake (RFC 1928, RFC 1929)
 */

#ifndef CANYON_SOCKS5_H
#define CANYON_SOCKS5_H

#include <stddef.h>

/*
 * Perform the SOCKS5 handshake on an already-connected TCP socket.
 *
 * Supports the CONNECT command, no-auth and username/password (RFC 1929)
 * authentication, and IPv4/IPv6/domain-name destinations.
 *
 * Returns 0 on success, -1 on failure (with an error message in err).
 */
int socks5_handshake(int fd, const char *host, int port,
                     const char *user, const char *pass,
                     char *err, size_t errlen);

#endif /* CANYON_SOCKS5_H */
