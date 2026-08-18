/*
 * rand.c - random byte source and PRNG helpers for canyon
 */

#include "canyon.h"
#include "rand.h"

int rand_open_source(const char *path)
{
    return open(path, O_RDONLY);
}

int rand_fill(int fd, void *buf, size_t n)
{
    char *p = buf;
    size_t got = 0;

    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            break;
        got += (size_t)r;
    }
    return (int)got;
}

static uint64_t s_state;

void rand_seed(const void *seed, size_t n)
{
    const uint8_t *b = seed;

    s_state = 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < n; i++) {
        s_state ^= (uint64_t)b[i] << ((i % 8) * 8);
        s_state ^= s_state >> 12;
        s_state ^= s_state << 25;
        s_state ^= s_state >> 27;
        s_state *= 2685821657736338717ULL;
    }
    if (s_state == 0)
        s_state = 1;
}

uint64_t rand_uint64(void)
{
    uint64_t x = s_state;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    s_state = x;
    return x * 2685821657736338717ULL;
}

uint64_t rand_range_u(uint64_t lo, uint64_t hi)
{
    if (hi <= lo)
        return lo;
    return lo + rand_uint64() % (hi - lo + 1);
}
