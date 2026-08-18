/*
 * net.h - socket helpers for canyon
 */

#ifndef CANYON_NET_H
#define CANYON_NET_H

#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

int net_connect_tcp(const char *host, int port, int timeout_ms,
                    char *err, size_t errlen);
int net_connect_udp(const char *host, int port,
                    char *err, size_t errlen);
ssize_t net_send_all(int fd, const void *buf, size_t n);

#endif /* CANYON_NET_H */
