/*
 * tls.c - optional TLS/SSL transport for canyon (OpenSSL)
 */

#include "canyon.h"
#include "tls.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <poll.h>

/* Wait (without holding the conn mutex) for the socket to become ready.
 * Returns true when ready, false on timeout/error. */
static bool tls_wait_fd(conn_t *c, short events, int timeout_ms)
{
    struct pollfd p;
    int r;

    p.fd = c->fd;
    p.events = events;
    do {
        r = poll(&p, 1, timeout_ms);
    } while (r < 0 && errno == EINTR);
    return r > 0;
}

void conn_init(conn_t *c, int fd)
{
    c->fd = fd;
    c->ssl = NULL;
    pthread_mutex_init(&c->lock, NULL);
}

bool conn_is_tls(conn_t *c)
{
    return c->ssl != NULL;
}

bool conn_has_pending(conn_t *c)
{
    int n;

    if (!c->ssl)
        return false;
    pthread_mutex_lock(&c->lock);
    n = SSL_pending(c->ssl);
    pthread_mutex_unlock(&c->lock);
    return n > 0;
}

int conn_tls(conn_t *c, const char *sni, const char *verify_name,
             bool verify, const char *ca_file, const char *alpn,
             char *err, size_t errlen)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        snprintf(err, errlen, "tls: cannot create SSL context");
        return -1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    if (verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (ca_file) {
            if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
                snprintf(err, errlen, "tls: cannot load CA file '%s'",
                         ca_file);
                SSL_CTX_free(ctx);
                return -1;
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);              /* SSL keeps its own reference */
    if (!ssl) {
        snprintf(err, errlen, "tls: cannot create SSL object");
        return -1;
    }

    SSL_set_fd(ssl, c->fd);

    if (alpn && alpn[0]) {
        size_t n = strlen(alpn);
        if (n < 255) {
            uint8_t proto[256];
            proto[0] = (uint8_t)n;
            memcpy(proto + 1, alpn, n);
            SSL_set_alpn_protos(ssl, proto, (unsigned)n + 1);
        }
    }
    if (sni && !is_ip_literal(sni))
        SSL_set_tlsext_host_name(ssl, sni);
    if (verify && verify_name)
        SSL_set1_host(ssl, verify_name);

    pthread_mutex_lock(&c->lock);
    int cr = SSL_connect(ssl);
    unsigned long e = cr == 1 ? 0 : ERR_get_error();
    pthread_mutex_unlock(&c->lock);

    if (cr != 1) {
        char ebuf[256];
        if (e == 0)
            snprintf(ebuf, sizeof ebuf, "connection closed during handshake");
        else
            ERR_error_string_n(e, ebuf, sizeof ebuf);
        snprintf(err, errlen, "tls: handshake failed: %s", ebuf);
        SSL_free(ssl);
        return -1;
    }

    if (verify && SSL_get_verify_result(ssl) != X509_V_OK) {
        snprintf(err, errlen, "tls: certificate verification failed");
        SSL_free(ssl);
        return -1;
    }

    /* Switch the socket to non-blocking mode. From here on SSL_read and
     * SSL_write never block while holding the conn mutex: WANT_READ and
     * WANT_WRITE are handled with poll() outside the lock, which lets the
     * sender and receiver threads coexist safely on the same SSL object. */
    int fl = fcntl(c->fd, F_GETFL, 0);
    if (fl < 0 || fcntl(c->fd, F_SETFL, fl | O_NONBLOCK) != 0) {
        snprintf(err, errlen, "tls: cannot set non-blocking mode: %s",
                 strerror(errno));
        SSL_free(ssl);
        return -1;
    }

    c->ssl = ssl;
    return 0;
}

ssize_t conn_send(conn_t *c, const void *buf, size_t n)
{
    if (!c->ssl)
        return send(c->fd, buf, n, MSG_NOSIGNAL);

    for (;;) {
        int r;
        int e = 0;

        pthread_mutex_lock(&c->lock);
        r = SSL_write(c->ssl, buf, (int)(n > INT_MAX ? INT_MAX : n));
        if (r <= 0)
            e = SSL_get_error(c->ssl, r);
        pthread_mutex_unlock(&c->lock);

        if (r > 0)
            return (ssize_t)r;
        if (e == SSL_ERROR_WANT_READ) {
            /* A post-handshake message (e.g. a TLS 1.3 ticket) must be read
             * before we may write again. Wait on POLLIN without the lock so
             * the receiver thread can drain it. */
            if (!tls_wait_fd(c, POLLIN, 1000))
                return -1;
            continue;
        }
        if (e == SSL_ERROR_WANT_WRITE) {
            if (!tls_wait_fd(c, POLLOUT, 5000))
                return -1;
            continue;
        }
        return -1;
    }
}

ssize_t conn_recv(conn_t *c, void *buf, size_t n)
{
    if (!c->ssl)
        return recv(c->fd, buf, n, 0);

    for (;;) {
        int r;
        int e = 0;

        pthread_mutex_lock(&c->lock);
        r = SSL_read(c->ssl, buf, (int)(n > INT_MAX ? INT_MAX : n));
        if (r <= 0)
            e = SSL_get_error(c->ssl, r);
        pthread_mutex_unlock(&c->lock);

        if (r > 0)
            return (ssize_t)r;
        if (e == SSL_ERROR_WANT_READ) {
            if (!tls_wait_fd(c, POLLIN, 5000)) {
                errno = EAGAIN;
                return -1;
            }
            continue;
        }
        if (e == SSL_ERROR_WANT_WRITE) {
            if (!tls_wait_fd(c, POLLOUT, 5000)) {
                errno = EAGAIN;
                return -1;
            }
            continue;
        }
        if (e == SSL_ERROR_ZERO_RETURN)
            return 0;
        return -1;
    }
}

ssize_t conn_send_all(conn_t *c, const void *buf, size_t n)
{
    const char *p = buf;
    size_t left = n;

    while (left > 0) {
        ssize_t r = conn_send(c, p, left);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            break;
        p += r;
        left -= (size_t)r;
    }
    return (ssize_t)(n - left);
}

void conn_shutdown(conn_t *c)
{
    if (c->ssl) {
        pthread_mutex_lock(&c->lock);
        SSL_shutdown(c->ssl);
        pthread_mutex_unlock(&c->lock);
    }
    shutdown(c->fd, SHUT_RDWR);
}

void conn_close(conn_t *c)
{
    if (c->ssl) {
        pthread_mutex_lock(&c->lock);
        SSL_free(c->ssl);
        c->ssl = NULL;
        pthread_mutex_unlock(&c->lock);
    }
    pthread_mutex_destroy(&c->lock);
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}