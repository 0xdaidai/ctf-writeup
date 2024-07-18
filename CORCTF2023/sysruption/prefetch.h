#ifndef PREFETCH_H
#define PREFETCH_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>

#define FLUSH_SIZE 4 * 1024 * 2014
/* How many iterations to perform is controlled by IORDER. Higher values will generally lead to more reliable results.
 * In practice, far less iterations are necessary esp. in non-virtualized environments */
#define IORDER 7
#define ITERATIONS 2 << IORDER
#define DEBUG 1
struct results
{
    void *addr;
    unsigned long minimum;
    unsigned long max_min;
    unsigned long average;
    unsigned significant;
};
enum analysis_type
{
    MINIMUM, //Find the lowest detecting slot
    MAXIMUM,
    MIN_EDGE,
    EDGE, //Find the edges
};

inline __attribute__((always_inline)) uint64_t rdtsc_begin();
inline __attribute__((always_inline)) uint64_t rdtsc_end();
static inline void prefetch(void *p);
static inline size_t onlyreload(void *addr);
struct results start_test(void *start, void *end, unsigned long step, enum analysis_type mode);
void* fetch_kaslr_base();
void* fetch_cea();
void* fetch_phy_base();

#endif /* MYLIB_H */