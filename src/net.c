/*
 * net.c - socket helpers for canyon
 */

#include "canyon.h"
#include "net.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>

static int net_connect_timeout(int fd, const struct sockaddr *sa,
                               socklen_t slen, int timeout_ms)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;

    int rc = connect(fd, sa, slen);
    if (rc != 0 && errno != EINPROGRESS)
        return -1;

    if (rc != 0) {
        struct pollfd p;
        p.fd = fd;
        p.events = POLLOUT;
        rc = poll(&p, 1, timeout_ms);
        if (rc <= 0)
            return -1;
        int soerr = 0;
        socklen_t l = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &l) != 0)
            return -1;
        if (soerr != 0) {
            errno = soerr;
            return -1;
        }
    }

    fcntl(fd, F_SETFL, flags);
    return 0;
}

int net_connect_tcp(const char *host, int port, int timeout_ms,
                    char *err, size_t errlen)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL, *it;
    char portstr[16];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(portstr, sizeof portstr, "%d", port);
    int rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        snprintf(err, errlen, "getaddrinfo(%s): %s", host, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;
        if (net_connect_timeout(fd, it->ai_addr, it->ai_addrlen,
                                timeout_ms) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0)
        snprintf(err, errlen, "connect to %s:%d failed: %s",
                 host, port, strerror(errno));
    return fd;
}

int net_connect_udp(const char *host, int port, char *err, size_t errlen)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL, *it;
    char portstr[16];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    snprintf(portstr, sizeof portstr, "%d", port);
    int rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        snprintf(err, errlen, "getaddrinfo(%s): %s", host, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0)
        snprintf(err, errlen, "connect UDP %s:%d failed: %s",
                 host, port, strerror(errno));
    return fd;
}

ssize_t net_send_all(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    size_t left = n;

    while (left > 0) {
        ssize_t r = send(fd, p, left, MSG_NOSIGNAL);
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
