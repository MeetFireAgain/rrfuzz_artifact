/**
 * RR-Fuzz Basic Block Trace Module
 * 
 * Records the Basic Block (BB) trace during program execution.
 * 
 * Design Goals:
 * 1. Efficiently record the PC address of each Translation Block (TB).
 * 2. Associate BB trace with the syscall trace for accurate execution sequencing.
 * 3. Support offline static analysis (e.g., angr CFG matching).
 */

#ifndef RR_BB_TRACE_H
#define RR_BB_TRACE_H

#include "qemu/osdep.h"
#include "user/abitypes.h"

/* Configuration Constants */

#define RR_BB_TRACE_BUFFER_SIZE (1024 * 1024)  // 1MB buffer
#define RR_BB_TRACE_SUFFIX ".bbl"              // BB trace file suffix

/* Data Structures */

/**
 * BB Trace Entry
 * One entry recorded for each TB execution.
 */
typedef struct {
    uint64_t pc;           // Program Counter (TB start address)
    uint32_t syscall_idx;  // Associated syscall index (0: pre-syscall, N: after Nth syscall)
    uint32_t flags;        // Reserved flags
} rr_bb_entry_t;

/**
 * BB Trace Context
 */
typedef struct {
    bool enabled;                          // Whether BB tracing is enabled
    char *trace_file;                      // Path to BB trace file
    int fd;                                // File descriptor
    
    /* Buffer */
    rr_bb_entry_t *buffer;                 // Memory buffer
    size_t buffer_size;                    // Buffer size (number of entries)
    size_t buffer_pos;                     // Current buffer position
    
    /* Statistics */
    uint64_t total_bbs;                    // Total BBs
    uint64_t total_flushes;                // Total flushes
    uint32_t current_syscall_idx;          // Current syscall index
    
    /* Address Filtering (Only record main program BBs) */
    bool filter_enabled;                   // Whether address filtering is enabled
    uint64_t main_start;                   // Start address of main program
    uint64_t main_end;                     // End address of main program
    uint64_t filtered_bbs;                 // Number of filtered BBs (stats)
} rr_bb_trace_t;

/* Global Variables */

extern rr_bb_trace_t *g_bb_trace;

/* Core Functions */

/**
 * Initialize BB trace module.
 * 
 * @param trace_file Path to syscall trace file (.bbl suffix will be added).
 * @return 0 on success, -1 on failure.
 */
int rr_bb_trace_init(const char *trace_file);

/**
 * Cleanup BB trace module.
 */
void rr_bb_trace_cleanup(void);

/**
 * Log a basic block execution.
 * 
 * Core function called during each TB execution.
 * 
 * @param pc Program Counter (TB start address).
 */
void rr_bb_trace_log(uint64_t pc);

/**
 * Flush buffer to disk.
 */
void rr_bb_trace_flush(void);

/**
 * Update current syscall index.
 * 
 * Should be called by the rr_record module whenever a syscall is recorded.
 * 
 * @param syscall_idx Syscall index.
 */
void rr_bb_trace_update_syscall_idx(uint32_t syscall_idx);

/**
 * Enable/Disable BB tracking.
 * 
 * @param enabled Whether to enable.
 */
void rr_bb_trace_set_enabled(bool enabled);

/**
 * Check if BB tracking is enabled (inline version).
 * 
 * @return true if enabled, false otherwise.
 */
static inline bool rr_bb_trace_is_enabled(void)
{
    return g_bb_trace && g_bb_trace->enabled;
}

/**
 * Check if BB tracking is enabled (non-inline version, for cpu-exec.c).
 * 
 * @return true if enabled, false otherwise.
 */
bool rr_bb_trace_is_enabled_check(void);

/**
 * Get BB trace statistics.
 * 
 * @param total_bbs Output: Total BBs.
 * @param total_flushes Output: Total flushes.
 */
void rr_bb_trace_get_stats(uint64_t *total_bbs, uint64_t *total_flushes);

/**
 * Print BB trace statistics.
 */
void rr_bb_trace_print_stats(void);

/**
 * Set main program address range (for filtering library BBs).
 * 
 * @param start_code Start address of main program code segment.
 * @param end_code End address of main program code segment.
 */
void rr_bb_trace_set_main_range(uint64_t start_code, uint64_t end_code);

/**
 * Get current BBs from buffer without flushing.
 * 
 * @param out_buffer Output buffer
 * @param max_count Max entries to copy
 * @return Number of entries copied
 */
uint32_t rr_bb_trace_get_current_buffer(uint64_t *out_buffer, uint32_t max_count);

/**
 * Enable/Disable address filtering.
 * 
 * @param enabled Whether to enable filtering.
 */
void rr_bb_trace_set_filter(bool enabled);

#endif /* RR_BB_TRACE_H */

