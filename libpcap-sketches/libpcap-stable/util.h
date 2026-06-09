#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <sys/time.h>

// Get current time in microseconds
static inline uint64_t now_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

#endif // UTIL_H