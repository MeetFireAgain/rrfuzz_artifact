/**
 * RR-Fuzz Coverage Tracking Module
 * 
 * Implements AFL-style edge coverage tracking
 */

#ifndef RR_COVERAGE_H
#define RR_COVERAGE_H

#include "qemu/osdep.h"
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/* ================= Configuration Constants ================= */

#define RR_COVERAGE_MAP_SIZE (64 * 1024)   // 64KB edge bitmap
#define RR_FLOW_HASH_MAP_SIZE (64 * 1024)  // 64KB flow hash bitmap
#define RR_COVERAGE_SHM_NAME "rr_coverage" // Shared memory name

/* ================= Data Structures ================= */

/**
 * Coverage Context
 */
typedef struct {
    bool enabled;                               // Whether coverage tracking is enabled
    uint8_t coverage_map[RR_COVERAGE_MAP_SIZE]; // Edge coverage bitmap
    uint8_t flow_hash_map[RR_FLOW_HASH_MAP_SIZE]; // Flow path hash bitmap (CFH)
    int shm_fd;                                // Shared memory file descriptor
    bool file_backed;                          // Use file as shared memory
    char backing_path[PATH_MAX];               // File path (only used in file_backed mode)
    
    /* Statistics */
    uint64_t total_edges;           // Total edge executions
    uint64_t unique_edges;          // Unique edges found
} rr_coverage_t;

/* ================= Global Variables ================= */

extern rr_coverage_t *g_base_coverage;
extern rr_coverage_t *g_coverage;

/* ================= Core Functions ================= */

/**
 * Initialize Coverage module
 */
int rr_coverage_init(const char *shm_name);

/**
 * Cleanup Coverage module
 */
void rr_coverage_cleanup(void);

/**
 * Record edge execution
 */
void rr_coverage_trace_edge(uint64_t cur_pc);

/**
 * Enable/Disable coverage tracking
 */
void rr_coverage_enable(void);
void rr_coverage_disable(void);

/**
 * Check if coverage tracking is enabled (inline version)
 */
static inline bool rr_coverage_is_enabled(void)
{
    return g_base_coverage && g_base_coverage->enabled;
}

/**
 * Check if coverage tracking is enabled (non-inline version)
 */
bool rr_coverage_is_enabled_check(void);

/**
 * Reset coverage map
 */
void rr_coverage_reset(void);

/**
 * Copy coverage map
 */
void rr_coverage_copy_map(uint8_t *dest);

/**
 * Get coverage statistics
 */
uint64_t rr_coverage_get_unique_edges(void);
uint64_t rr_coverage_get_total_edges(void);

/**
 * Set target program address range
 */
void rr_set_target_range(uint64_t start, uint64_t end);

/**
 * Check if address is within target range
 */
bool rr_in_target_range(uint64_t pc);

#endif /* RR_COVERAGE_H */
