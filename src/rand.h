/*
 * rand.h - random byte source and PRNG helpers for canyon
 */

#ifndef CANYON_RAND_H
#define CANYON_RAND_H

#include <stddef.h>
#include <stdint.h>

/*
 * Open the file used as the random byte source (e.g. /dev/urandom).
 * Returns a file descriptor, or -1 on error.
 */
int rand_open_source(const char *path);

/*
 * Read up to n random bytes into buf, looping until the buffer is full
 * or the source returns EOF. Returns the number of bytes read, or -1
 * on error.
 */
int rand_fill(int fd, void *buf, size_t n);

/* Seed the internal PRNG (used for chunk sizes and delays). */
void rand_seed(const void *seed, size_t n);

uint64_t rand_uint64(void);
uint64_t rand_range_u(uint64_t lo, uint64_t hi);

#endif /* CANYON_RAND_H */
