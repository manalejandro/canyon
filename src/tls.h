/*
 * tls.h - optional TLS/SSL transport for canyon
 *
 * conn_t abstracts a connection that is either a plain TCP socket or a
 * TLS-wrapped socket (OpenSSL). This lets canyon audit HTTPS and WSS
 * endpoints with the same send/recv code paths.
 *
 * TLS is enabled per connection with conn_tls(); when it is not called
 * the conn_t behaves exactly like the raw socket.
 */

#ifndef CANYON_TLS_H
#define CANYON_TLS_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include <openssl/ssl.h>

typedef struct {
    int fd;
    SSL *ssl;
    pthread_mutex_t lock;
} conn_t;

/*
 * Initialise a plain (non-TLS) connection wrapping the given fd.
 * The fd is owned by the conn_t from now on.
 */
void conn_init(conn_t *c, int fd);

/*
 * conn_t may be used from two threads concurrently (canyon runs a sender
 * and a receiver thread on the same connection). All SSL_* calls are
 * serialised internally with a mutex; OpenSSL SSL objects are not safe
 * for concurrent SSL_read/SSL_write on the same SSL*.
 */

/*
 * Upgrade the connection to TLS (client handshake).
 *
 *   sni          hostname for the SNI extension, or NULL to omit it
 *   verify_name  hostname to verify the certificate against, used only
 *                when verify is true
 *   verify       verify the server certificate
 *   ca_file      PEM CA bundle to trust, or NULL for the system store
 *                (only used when verify is true)
 *   alpn         ALPN protocol string to offer (e.g. "http/1.1") or NULL
 *
 * Returns 0 on success, -1 on failure (message in err).
 */
int conn_tls(conn_t *c, const char *sni, const char *verify_name,
             bool verify, const char *ca_file, const char *alpn,
             char *err, size_t errlen);

bool conn_is_tls(conn_t *c);

/* Returns true when the TLS layer still has decrypted bytes buffered. */
bool conn_has_pending(conn_t *c);

/* Send/receive, handling both the plain and TLS paths. */
ssize_t conn_send(conn_t *c, const void *buf, size_t n);
ssize_t conn_recv(conn_t *c, void *buf, size_t n);

/* Send the whole buffer (loops over short writes / TLS WANT states). */
ssize_t conn_send_all(conn_t *c, const void *buf, size_t n);

/* Close the read/write direction (unblocks pending recv/SSL calls). */
void conn_shutdown(conn_t *c);

/* Free TLS state and close the fd. */
void conn_close(conn_t *c);

#endif /* CANYON_TLS_H */