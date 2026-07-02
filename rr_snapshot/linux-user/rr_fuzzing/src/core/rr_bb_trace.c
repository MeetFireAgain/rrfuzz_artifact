/**
 * RR-Fuzz Basic Block Trace Module - Implementation
 */

#include "rr_bb_trace.h"
#include "rr_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* ================= Global Variables ================= */

rr_bb_trace_t *g_bb_trace = NULL;

/* ================= Internal Helper Functions ================= */

/**
 * Constructs the BB trace file path.
 */
static char *construct_bb_trace_path(const char *trace_file)
{
    if (!trace_file) {
        return NULL;
    }
    
    size_t len = strlen(trace_file) + strlen(RR_BB_TRACE_SUFFIX) + 1;
    char *bb_path = malloc(len);
    if (!bb_path) {
        RR_ERROR("Failed to allocate memory for BB trace path");
        return NULL;
    }
    
    snprintf(bb_path, len, "%s%s", trace_file, RR_BB_TRACE_SUFFIX);
    return bb_path;
}

/* ================= Core Function Implementation ================= */

int rr_bb_trace_init(const char *trace_file)
{
    if (!trace_file) {
        RR_ERROR("BB trace: trace_file is NULL");
        return -1;
    }
    
    /* Allocate context */
    g_bb_trace = calloc(1, sizeof(rr_bb_trace_t));
    if (!g_bb_trace) {
        RR_ERROR("Failed to allocate BB trace context");
        return -1;
    }
    
    /* Construct BB trace file path */
    const char *env_bb_path = getenv("RR_BB_TRACE_FILE");
    if (env_bb_path && strlen(env_bb_path) > 0) {
        g_bb_trace->trace_file = strdup(env_bb_path);
    } else {
        g_bb_trace->trace_file = construct_bb_trace_path(trace_file);
    }

    if (!g_bb_trace->trace_file) {
        free(g_bb_trace);
        g_bb_trace = NULL;
        return -1;
    }
    
    /* Open file */
    g_bb_trace->fd = open(g_bb_trace->trace_file, 
                          O_WRONLY | O_CREAT | O_TRUNC, 
                          0644);
    if (g_bb_trace->fd < 0) {
        RR_ERROR("Failed to open BB trace file '%s': %s",
                g_bb_trace->trace_file, strerror(errno));
        free(g_bb_trace->trace_file);
        free(g_bb_trace);
        g_bb_trace = NULL;
        return -1;
    }
    
    /* Allocate buffer */
    g_bb_trace->buffer_size = RR_BB_TRACE_BUFFER_SIZE / sizeof(rr_bb_entry_t);
    g_bb_trace->buffer = malloc(RR_BB_TRACE_BUFFER_SIZE);
    if (!g_bb_trace->buffer) {
        RR_ERROR("Failed to allocate BB trace buffer");
        close(g_bb_trace->fd);
        free(g_bb_trace->trace_file);
        free(g_bb_trace);
        g_bb_trace = NULL;
        return -1;
    }
    
    /* Initialize status */
    g_bb_trace->buffer_pos = 0;
    g_bb_trace->total_bbs = 0;
    g_bb_trace->total_flushes = 0;
    g_bb_trace->current_syscall_idx = 0;
    g_bb_trace->enabled = true;
    
    RR_INFO("BB trace initialized: %s (buffer: %zu entries)",
            g_bb_trace->trace_file, g_bb_trace->buffer_size);
            
    return 0;
}

void rr_bb_trace_cleanup(void)
{
    if (!g_bb_trace) {
        return;
    }
    
    /* Flush remaining data */
    if (g_bb_trace->buffer_pos > 0) {
        rr_bb_trace_flush();
    }
    
    /* Print statistics */
    rr_bb_trace_print_stats();
    
    /* Close file */
    if (g_bb_trace->fd >= 0) {
        close(g_bb_trace->fd);
    }
    
    /* Free resources */
    if (g_bb_trace->buffer) {
        free(g_bb_trace->buffer);
    }
    if (g_bb_trace->trace_file) {
        free(g_bb_trace->trace_file);
    }
    
    free(g_bb_trace);
    g_bb_trace = NULL;
    
    RR_INFO("BB trace cleanup completed");
}

void rr_bb_trace_log(uint64_t pc)
{
    if (!rr_bb_trace_is_enabled()) {
        return;
    }
    
    if (g_bb_trace->filter_enabled) {
        if (pc < g_bb_trace->main_start || pc >= g_bb_trace->main_end) {
            /* Skip library function basic blocks */
            g_bb_trace->filtered_bbs++;
            return;
        }
    }
    
    /* Check if buffer is full */
    if (g_bb_trace->buffer_pos >= g_bb_trace->buffer_size) {
        rr_bb_trace_flush();
    }
    
    /* Record basic block */
    rr_bb_entry_t *entry = &g_bb_trace->buffer[g_bb_trace->buffer_pos];
    entry->pc = pc;
    entry->syscall_idx = g_bb_trace->current_syscall_idx;
    entry->flags = 0;
    
    g_bb_trace->buffer_pos++;
    g_bb_trace->total_bbs++;
    

}

void rr_bb_trace_flush(void)
{
    if (!g_bb_trace || g_bb_trace->buffer_pos == 0) {
        return;
    }
    
    size_t bytes_to_write = g_bb_trace->buffer_pos * sizeof(rr_bb_entry_t);
    ssize_t written = write(g_bb_trace->fd, g_bb_trace->buffer, bytes_to_write);
    
    if (written != (ssize_t)bytes_to_write) {
        RR_ERROR("Failed to write BB trace: expected %zu bytes, wrote %zd",
                bytes_to_write, written);
        return;
    }
    
    g_bb_trace->total_flushes++;
    g_bb_trace->buffer_pos = 0;
    
    RR_TRACE("BB trace flushed: %zu entries", 
            bytes_to_write / sizeof(rr_bb_entry_t));
}

void rr_bb_trace_update_syscall_idx(uint32_t syscall_idx)
{
    if (g_bb_trace) {
        g_bb_trace->current_syscall_idx = syscall_idx;
        RR_TRACE("BB trace syscall index updated to %u", syscall_idx);
    }
}

void rr_bb_trace_set_enabled(bool enabled)
{
    if (g_bb_trace) {
        g_bb_trace->enabled = enabled;
        RR_INFO("BB trace %s", enabled ? "enabled" : "disabled");
    }
}

/* Non-inline version for cpu-exec.c */
bool rr_bb_trace_is_enabled_check(void)
{
    return g_bb_trace && g_bb_trace->enabled;
}

void rr_bb_trace_get_stats(uint64_t *total_bbs, uint64_t *total_flushes)
{
    if (g_bb_trace) {
        if (total_bbs) {
            *total_bbs = g_bb_trace->total_bbs;
        }
        if (total_flushes) {
            *total_flushes = g_bb_trace->total_flushes;
        }
    }
}

void rr_bb_trace_print_stats(void)
{
    if (!g_bb_trace) {
        return;
    }
    
    RR_INFO("=== BB Trace Statistics ===");
    RR_INFO("  Total BBs recorded: %lu", g_bb_trace->total_bbs);
    RR_INFO("  Total flushes: %lu", g_bb_trace->total_flushes);
    RR_INFO("  Buffer size: %zu entries", g_bb_trace->buffer_size);
    RR_INFO("  Current syscall idx: %u", g_bb_trace->current_syscall_idx);
    
    if (g_bb_trace->total_flushes > 0) {
        RR_INFO("  Avg BBs per flush: %.2f", 
                (double)g_bb_trace->total_bbs / (double)g_bb_trace->total_flushes);
    }
    
    if (g_bb_trace->filter_enabled) {
        RR_INFO("  Filtered BBs (lib): %lu", g_bb_trace->filtered_bbs);
        RR_INFO("  Main program range: 0x%lx - 0x%lx",
                g_bb_trace->main_start, g_bb_trace->main_end);
    }
}

void rr_bb_trace_set_main_range(uint64_t start_code, uint64_t end_code)
{
    if (!g_bb_trace) return;
    g_bb_trace->main_start = start_code;
    g_bb_trace->main_end = end_code;
}

uint32_t rr_bb_trace_get_current_buffer(uint64_t *out_buffer, uint32_t max_count)
{
    if (!g_bb_trace || g_bb_trace->buffer_pos == 0) {
        return 0;
    }

    uint32_t count = g_bb_trace->buffer_pos;
    if (count > max_count) {
        count = max_count;
    }

    for (uint32_t i = 0; i < count; i++) {
        out_buffer[i] = g_bb_trace->buffer[i].pc;
    }

    return count;
}

void rr_bb_trace_set_filter(bool enabled)
{
    if (!g_bb_trace) return;
    g_bb_trace->filter_enabled = enabled;
}
