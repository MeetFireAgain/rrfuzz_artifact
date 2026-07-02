/**
 * Mapping Manager - Optimized data structures and algorithms for FD and address mapping.
 */

#ifndef RR_MAPPING_MANAGER_H
#define RR_MAPPING_MANAGER_H

#include "rr_framework.h"
#include <stdint.h>
#include <stdbool.h>

/* ==================== FD Mapping Management ==================== */

typedef struct rr_fd_mapping {
    int recorded_fd;
    int actual_fd;
    uint64_t timestamp;  // For LRU eviction
    struct rr_fd_mapping *next;
} rr_fd_mapping_t;

typedef struct {
    rr_fd_mapping_t **buckets;
    size_t bucket_count;
    size_t total_mappings;
    uint64_t access_counter;
} rr_fd_mapping_table_t;

/* ==================== Address Mapping Management ==================== */

typedef struct rr_addr_mapping {
    target_ulong recorded_addr;
    target_ulong actual_addr;
    size_t size;
    uint64_t timestamp;
    struct rr_addr_mapping *next;
} rr_addr_mapping_t;

typedef struct {
    rr_addr_mapping_t **buckets;
    size_t bucket_count;
    size_t total_mappings;
    uint64_t access_counter;
} rr_addr_mapping_table_t;

/* ==================== Statistics ==================== */

typedef struct {
    uint64_t fd_lookups;
    uint64_t fd_hits;
    uint64_t fd_misses;
    uint64_t addr_lookups;
    uint64_t addr_hits;
    uint64_t addr_misses;
    uint64_t collisions;
    double avg_chain_length;
} rr_mapping_stats_t;

/* ==================== Public Interface ==================== */

/* Note: Core interfaces are declared in rr_framework.h; only extensions here. */

/* Extended FD mapping operations */
bool rr_fd_mapping_exists(int recorded_fd);

/* Extended address mapping operations */
bool rr_addr_mapping_exists(target_ulong recorded_addr);

/* Batch operations */
int rr_fd_mapping_add_batch(const int *recorded_fds, const int *actual_fds, size_t count);
int rr_addr_mapping_add_batch(const target_ulong *recorded_addrs, 
                             const target_ulong *actual_addrs, 
                             const size_t *sizes, size_t count);

/* Statistics and debugging */
void rr_mapping_get_stats(rr_mapping_stats_t *stats);
void rr_mapping_print_stats(void);
void rr_mapping_reset_stats(void);

/* Memory management optimization */
void rr_mapping_gc(void);  // Garbage collection
void rr_mapping_rehash(void);  // Rehash functionality

#endif /* RR_MAPPING_MANAGER_H */
