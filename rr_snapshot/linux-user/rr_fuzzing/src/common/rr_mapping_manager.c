/**
 * Mapping Manager Implementation - Efficient FD and address mapping management.
 */

#include "rr_mapping_manager.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ==================== Global Variables ==================== */

static rr_fd_mapping_table_t *g_fd_table = NULL;
static rr_addr_mapping_table_t *g_addr_table = NULL;
static rr_mapping_stats_t g_stats = {0};
static bool g_initialized = false;

/* ==================== Hash Functions ==================== */

static inline size_t hash_fd(int fd, size_t bucket_count) {
    // Use a simple but effective hash function
    return ((unsigned int)fd * 2654435761U) % bucket_count;
}

static inline size_t hash_addr(target_ulong addr, size_t bucket_count) {
    // Hash address considering page alignment (4KB pages)
    return ((addr >> 12) * 2654435761U) % bucket_count;
}

/* ==================== FD Mapping Implementation ==================== */

static rr_fd_mapping_t* create_fd_mapping(int recorded_fd, int actual_fd) {
    rr_fd_mapping_t *mapping = malloc(sizeof(rr_fd_mapping_t));
    if (!mapping) return NULL;
    
    mapping->recorded_fd = recorded_fd;
    mapping->actual_fd = actual_fd;
    mapping->timestamp = ++g_fd_table->access_counter;
    mapping->next = NULL;
    return mapping;
}

static void free_fd_mapping(rr_fd_mapping_t *mapping) {
    if (mapping) {
        free(mapping);
    }
}

/**
 * @brief Add a new FD mapping record
 * 
 * In Replay/Fuzzing mode, when the guest program executes syscalls like open/dup/socket 
 * that create a new FD, the actual FD (actual_fd) might differ from the FD recorded in the trace (recorded_fd).
 * This function records the mapping for subsequent system calls.
 * 
 * **Use Cases**:
 * - open/openat: Map the new open FD.
 * - dup/dup2/dup3: Map the duplicated FD.
 * - socket/accept: Map the network socket FD.
 * 
 * @param recorded_fd FD recorded in the trace (record stage).
 * @param actual_fd FD actually obtained during replay.
 * 
 * @return int 
 *         - 0: Mapping added successfully (new or updated).
 *         - -1: Failed (memory error or uninitialized).
 * 
 * @note Updates actual_fd and access timestamp if mapping already exists.
 * @note Uses hash table for O(1) lookup.
 * @note Performance critical as this is a high-frequency call.
 */
int rr_fd_mapping_add(int recorded_fd, int actual_fd) {
    if (!g_initialized || !g_fd_table) return -1;
    
    size_t bucket = hash_fd(recorded_fd, g_fd_table->bucket_count);
    
    // Check if mapping already exists
    rr_fd_mapping_t *current = g_fd_table->buckets[bucket];
    while (current) {
        if (current->recorded_fd == recorded_fd) {
            // Update existing mapping
            current->actual_fd = actual_fd;
            current->timestamp = ++g_fd_table->access_counter;
            return 0;
        }
        current = current->next;
    }
    
    // Create new mapping
    rr_fd_mapping_t *new_mapping = create_fd_mapping(recorded_fd, actual_fd);
    if (!new_mapping) return -1;
    
    // Insert at bucket head
    new_mapping->next = g_fd_table->buckets[bucket];
    g_fd_table->buckets[bucket] = new_mapping;
    g_fd_table->total_mappings++;
    
    return 0;
}

/**
 * @brief Look up FD mapping to get the current actual FD
 * 
 * When the guest program attempts to use an FD (e.g., read/write/close), the trace's
 * recorded_fd must be converted to the current valid actual_fd.
 * 
 * @param recorded_fd FD recorded in the trace.
 * 
 * @return int
 *         - On success: Returns the corresponding actual_fd.
 *         - On failure: Returns original recorded_fd (fallback).
 * 
 * @note Updates statistics (lookups, hits, misses) and access timestamp (LRU).
 * @note Returns recorded_fd directly if manager is not initialized.
 * 
 * @warning Callers must handle cases where returned FD may be invalid (though rare in replay).
 */
int rr_fd_mapping_get(int recorded_fd) {
    if (!g_initialized || !g_fd_table) return recorded_fd;
    
    g_stats.fd_lookups++;
    
    size_t bucket = hash_fd(recorded_fd, g_fd_table->bucket_count);
    rr_fd_mapping_t *current = g_fd_table->buckets[bucket];
    
    while (current) {
        if (current->recorded_fd == recorded_fd) {
            current->timestamp = ++g_fd_table->access_counter;
            g_stats.fd_hits++;
            return current->actual_fd;
        }
        current = current->next;
    }
    
    g_stats.fd_misses++;
    return recorded_fd;  // Mapping not found, fallback to original
}

int rr_fd_mapping_remove(int recorded_fd) {
    if (!g_initialized || !g_fd_table) return -1;
    
    size_t bucket = hash_fd(recorded_fd, g_fd_table->bucket_count);
    rr_fd_mapping_t **current = &g_fd_table->buckets[bucket];
    
    while (*current) {
        if ((*current)->recorded_fd == recorded_fd) {
            rr_fd_mapping_t *to_remove = *current;
            *current = (*current)->next;
            free_fd_mapping(to_remove);
            g_fd_table->total_mappings--;
            return 0;
        }
        current = &(*current)->next;
    }
    
    return -1;  // Not found
}

bool rr_fd_mapping_exists(int recorded_fd) {
    if (!g_initialized || !g_fd_table) return false;
    
    size_t bucket = hash_fd(recorded_fd, g_fd_table->bucket_count);
    rr_fd_mapping_t *current = g_fd_table->buckets[bucket];
    
    while (current) {
        if (current->recorded_fd == recorded_fd) {
            return true;
        }
        current = current->next;
    }
    
    return false;
}

/* ==================== Address Mapping Implementation ==================== */

static rr_addr_mapping_t* create_addr_mapping(target_ulong recorded_addr, 
                                             target_ulong actual_addr, size_t size) {
    rr_addr_mapping_t *mapping = malloc(sizeof(rr_addr_mapping_t));
    if (!mapping) return NULL;
    
    mapping->recorded_addr = recorded_addr;
    mapping->actual_addr = actual_addr;
    mapping->size = size;
    mapping->timestamp = ++g_addr_table->access_counter;
    mapping->next = NULL;
    return mapping;
}

static void free_addr_mapping(rr_addr_mapping_t *mapping) {
    if (mapping) {
        free(mapping);
    }
}

/**
 * @brief Add a new address mapping record
 * 
 * Like FD mappings, memory addresses returned by mmap/brk typically differ between
 * Record and Replay stages due to ASLR. This function records the address delta.
 * 
 * @param recorded_addr Memory address recorded in the trace.
 * @param actual_addr Memory address actually obtained during replay.
 * @param size Size of the memory region (bytes).
 * 
 * @return int
 *         - 0: Successful.
 *         - -1: Failed.
 * 
 * @note Used for mmap, mremap, shmat syscalls.
 * @note Region size is recorded to support Range Queries.
 */
int rr_addr_mapping_add(target_ulong recorded_addr, target_ulong actual_addr, size_t size) {
    if (!g_initialized || !g_addr_table) return -1;
    
    size_t bucket = hash_addr(recorded_addr, g_addr_table->bucket_count);
    
    // Check if mapping already exists
    rr_addr_mapping_t *current = g_addr_table->buckets[bucket];
    while (current) {
        if (current->recorded_addr == recorded_addr) {
            // Update existing mapping
            current->actual_addr = actual_addr;
            current->size = size;
            current->timestamp = ++g_addr_table->access_counter;
            return 0;
        }
        current = current->next;
    }
    
    // Create new mapping
    rr_addr_mapping_t *new_mapping = create_addr_mapping(recorded_addr, actual_addr, size);
    if (!new_mapping) return -1;
    
    // Insert at bucket head
    new_mapping->next = g_addr_table->buckets[bucket];
    g_addr_table->buckets[bucket] = new_mapping;
    g_addr_table->total_mappings++;
    
    return 0;
}

/**
 * @brief Look up address mapping - supports exact and range matching
 * 
 * Converts recorded_addr to the current actual_addr.
 * 
 * **Query Strategies**:
 * 1. **Exact Match** (Fast Path): O(1) hash lookup. Used for operations like munmap(base_addr).
 * 2. **Range Match** (Slow Path): O(N) traversal. Used for munmap(base + offset) 
 *    or accessing mapped memory via pointer arithmetic.
 * 
 * @param recorded_addr Address recorded in the trace.
 * 
 * @return target_ulong
 *         - Mapped actual address (mapped_base + offset).
 *         - If not found, returns original recorded_addr.
 * 
 * @note Range matching handles pointers into mapped regions.
 * @note Performance overhead applies to range matching; usage should be minimized.
 * @warning Range matching currently uses linear traversal; scaling concerns exist.
 */
target_ulong rr_addr_mapping_get(target_ulong recorded_addr) {
    if (!g_initialized || !g_addr_table) return recorded_addr;
    
    g_stats.addr_lookups++;
    
    // Fast Path: Try exact match
    size_t bucket = hash_addr(recorded_addr, g_addr_table->bucket_count);
    rr_addr_mapping_t *current = g_addr_table->buckets[bucket];
    
    while (current) {
        if (current->recorded_addr == recorded_addr) {
            current->timestamp = ++g_addr_table->access_counter;
            g_stats.addr_hits++;
            return current->actual_addr;
        }
        current = current->next;
    }
    
    // Slow Path: Try range query
    // Traverse all buckets to find mapping containing this address
    for (size_t i = 0; i < g_addr_table->bucket_count; i++) {
        current = g_addr_table->buckets[i];
        while (current) {
            target_ulong range_start = current->recorded_addr;
            target_ulong range_end = current->recorded_addr + current->size;
            
            if (recorded_addr >= range_start && recorded_addr < range_end) {
                // Mapping found; calculate offset
                target_ulong offset = recorded_addr - range_start;
                target_ulong mapped_addr = current->actual_addr + offset;
                
                current->timestamp = ++g_addr_table->access_counter;
                g_stats.addr_hits++;
                
                fprintf(stderr, "[ADDR-RANGE-MAPPING] addr=0x%lx in range [0x%lx-0x%lx], offset=0x%lx, mapped=0x%lx\n",
                        (unsigned long)recorded_addr,
                        (unsigned long)range_start, (unsigned long)range_end,
                        (unsigned long)offset, (unsigned long)mapped_addr);
                
                return mapped_addr;
            }
            current = current->next;
        }
    }
    
    g_stats.addr_misses++;
    return recorded_addr;  // Mapping not found, fallback to original
}

int rr_addr_mapping_remove(target_ulong recorded_addr) {
    if (!g_initialized || !g_addr_table) return -1;
    
    size_t bucket = hash_addr(recorded_addr, g_addr_table->bucket_count);
    rr_addr_mapping_t **current = &g_addr_table->buckets[bucket];
    
    while (*current) {
        if ((*current)->recorded_addr == recorded_addr) {
            rr_addr_mapping_t *to_remove = *current;
            *current = (*current)->next;
            free_addr_mapping(to_remove);
            g_addr_table->total_mappings--;
            return 0;
        }
        current = &(*current)->next;
    }
    
    return -1;  // Not found
}

bool rr_addr_mapping_exists(target_ulong recorded_addr) {
    if (!g_initialized || !g_addr_table) return false;
    
    size_t bucket = hash_addr(recorded_addr, g_addr_table->bucket_count);
    rr_addr_mapping_t *current = g_addr_table->buckets[bucket];
    
    while (current) {
        if (current->recorded_addr == recorded_addr) {
            return true;
        }
        current = current->next;
    }
    
    return false;
}

/* ==================== Batch Operations ==================== */

int rr_fd_mapping_add_batch(const int *recorded_fds, const int *actual_fds, size_t count) {
    if (!recorded_fds || !actual_fds || count == 0) return -1;
    
    int success_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (rr_fd_mapping_add(recorded_fds[i], actual_fds[i]) == 0) {
            success_count++;
        }
    }
    
    return success_count;
}

int rr_addr_mapping_add_batch(const target_ulong *recorded_addrs, 
                             const target_ulong *actual_addrs, 
                             const size_t *sizes, size_t count) {
    if (!recorded_addrs || !actual_addrs || !sizes || count == 0) return -1;
    
    int success_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (rr_addr_mapping_add(recorded_addrs[i], actual_addrs[i], sizes[i]) == 0) {
            success_count++;
        }
    }
    
    return success_count;
}

/* ==================== Initialization and Cleanup ==================== */

int rr_mapping_manager_init(size_t fd_buckets, size_t addr_buckets) {
    if (g_initialized) {
        return 0;  // Already initialized
    }
    
    // Initialize FD table
    g_fd_table = malloc(sizeof(rr_fd_mapping_table_t));
    if (!g_fd_table) return -1;
    
    g_fd_table->bucket_count = fd_buckets > 0 ? fd_buckets : 256;
    g_fd_table->buckets = calloc(g_fd_table->bucket_count, sizeof(rr_fd_mapping_t*));
    if (!g_fd_table->buckets) {
        free(g_fd_table);
        return -1;
    }
    g_fd_table->total_mappings = 0;
    g_fd_table->access_counter = 0;
    
    // Initialize Address table
    g_addr_table = malloc(sizeof(rr_addr_mapping_table_t));
    if (!g_addr_table) {
        free(g_fd_table->buckets);
        free(g_fd_table);
        return -1;
    }
    
    g_addr_table->bucket_count = addr_buckets > 0 ? addr_buckets : 128;
    g_addr_table->buckets = calloc(g_addr_table->bucket_count, sizeof(rr_addr_mapping_t*));
    if (!g_addr_table->buckets) {
        free(g_fd_table->buckets);
        free(g_fd_table);
        free(g_addr_table);
        return -1;
    }
    g_addr_table->total_mappings = 0;
    g_addr_table->access_counter = 0;
    
    // Reset statistics
    memset(&g_stats, 0, sizeof(g_stats));
    
    g_initialized = true;
    return 0;
}

void rr_mapping_manager_cleanup(void) {
    if (!g_initialized) return;
    
    // Cleanup FD table
    if (g_fd_table) {
        for (size_t i = 0; i < g_fd_table->bucket_count; i++) {
            rr_fd_mapping_t *current = g_fd_table->buckets[i];
            while (current) {
                rr_fd_mapping_t *next = current->next;
                free_fd_mapping(current);
                current = next;
            }
        }
        free(g_fd_table->buckets);
        free(g_fd_table);
        g_fd_table = NULL;
    }
    
    // Cleanup Address table
    if (g_addr_table) {
        for (size_t i = 0; i < g_addr_table->bucket_count; i++) {
            rr_addr_mapping_t *current = g_addr_table->buckets[i];
            while (current) {
                rr_addr_mapping_t *next = current->next;
                free_addr_mapping(current);
                current = next;
            }
        }
        free(g_addr_table->buckets);
        free(g_addr_table);
        g_addr_table = NULL;
    }
    
    g_initialized = false;
}

/* ==================== Statistics and Debugging ==================== */

void rr_mapping_get_stats(rr_mapping_stats_t *stats) {
    if (!stats) return;
    
    *stats = g_stats;
    
    // Calculate average chain length
    if (g_fd_table && g_addr_table) {
        size_t total_chains = 0;
        size_t total_length = 0;
        
        // FD table chain lengths
        for (size_t i = 0; i < g_fd_table->bucket_count; i++) {
            size_t chain_length = 0;
            rr_fd_mapping_t *current = g_fd_table->buckets[i];
            while (current) {
                chain_length++;
                current = current->next;
            }
            if (chain_length > 0) {
                total_chains++;
                total_length += chain_length;
            }
        }
        
        // Address table chain lengths
        for (size_t i = 0; i < g_addr_table->bucket_count; i++) {
            size_t chain_length = 0;
            rr_addr_mapping_t *current = g_addr_table->buckets[i];
            while (current) {
                chain_length++;
                current = current->next;
            }
            if (chain_length > 0) {
                total_chains++;
                total_length += chain_length;
            }
        }
        
        stats->avg_chain_length = total_chains > 0 ? (double)total_length / total_chains : 0.0;
    }
}

void rr_mapping_print_stats(void) {
    rr_mapping_stats_t stats;
    rr_mapping_get_stats(&stats);
    
    printf("=== RR Mapping Manager Statistics ===\n");
    printf("FD Mappings:\n");
    printf("  Lookups: %lu, Hits: %lu, Misses: %lu\n", 
           stats.fd_lookups, stats.fd_hits, stats.fd_misses);
    printf("  Hit Rate: %.2f%%\n", 
           stats.fd_lookups > 0 ? (double)stats.fd_hits / stats.fd_lookups * 100.0 : 0.0);
    
    printf("Address Mappings:\n");
    printf("  Lookups: %lu, Hits: %lu, Misses: %lu\n", 
           stats.addr_lookups, stats.addr_hits, stats.addr_misses);
    printf("  Hit Rate: %.2f%%\n", 
           stats.addr_lookups > 0 ? (double)stats.addr_hits / stats.addr_lookups * 100.0 : 0.0);
    
    printf("Performance:\n");
    printf("  Average Chain Length: %.2f\n", stats.avg_chain_length);
    printf("  Total Mappings: FD=%zu, Addr=%zu\n", 
           g_fd_table ? g_fd_table->total_mappings : 0,
           g_addr_table ? g_addr_table->total_mappings : 0);
}

void rr_mapping_reset_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}

/* ==================== Memory Management Optimization ==================== */

void rr_mapping_gc(void) {
    // TODO: Implement LRU-based garbage collection
    // Clean up oldest mappings when capacity is exceeded
}

void rr_mapping_rehash(void) {
    // TODO: Implement dynamic rehashing
    // Increase bucket count and redistribute when chain length threshold is exceeded
}
