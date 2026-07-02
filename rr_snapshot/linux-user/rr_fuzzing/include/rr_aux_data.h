/*
 * RR-Fuzz Auxiliary Data System
 * 
 * Inspired by EnvFuzz's AUX system for recording buffer contents,
 * structures, and other data associated with syscall arguments.
 * 
 * This enables Pure Deterministic Replay by capturing actual data
 * instead of just pointers.
 */

#ifndef RR_AUX_DATA_H
#define RR_AUX_DATA_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

/* Data kinds - matches EnvFuzz categories */
typedef enum {
    AUX_NONE = 0,
    AUX_BUFFER,         /* Raw buffer (ABUF) */
    AUX_STRING,         /* String (ASTR) */
    AUX_IOV,            /* iovec array (AIOV) */
    AUX_MSG,            /* msghdr (AMSG) */
    AUX_STAT,           /* stat structure (ASTB) */
    AUX_TIMEVAL,        /* timeval (A_TV) */
    AUX_TIMESPEC,       /* timespec (A_TS) */
    AUX_POLLFD,         /* pollfd array (APFD) */
    AUX_FDSET,          /* fd_set (ASET) */
    AUX_MMAP_CONTENT,   /* mmap file content */
    AUX_SCALAR,         /* simple scalar value */
    AUX_STRUCT,         /* generic structured data */
    AUX_IOCTL_OUTPUT,   /* ioctl output buffer (task2) */
} rr_aux_kind_t;

typedef struct {
    uint64_t addr;
    uint64_t length;
    int64_t prot;
    int64_t flags;
    int64_t fd;
    uint64_t offset;
} rr_aux_mmap_info_t;

typedef struct {
    uint64_t addr;
    uint64_t len;
    int64_t extra1;
    int64_t extra2;
} rr_aux_mm_params_t;

/* Single auxiliary data entry */
typedef struct rr_aux_data {
    struct rr_aux_data *next;   /* Linked list for multiple aux entries */
    
    rr_aux_kind_t kind;         /* Data type */
    uint8_t arg_mask;           /* Which argument (bit mask) */
    uint32_t size;              /* Data size in bytes */
    uint8_t *data;              /* Actual data content */
    
    /* Optional metadata */
    char *external_file;        /* Path to external data file (if large) */
    bool is_external;           /* Data stored externally? */
} rr_aux_data_t;

/* Configuration */
#define AUX_MAX_INLINE_SIZE  (4 * 1024)       /* 4KB inline threshold */
#define AUX_MAX_RECORD_SIZE  (64 * 1024)      /* 64KB total threshold */

/* API Functions */

/**
 * Create a new auxiliary data entry
 */
/**
 * @brief Create a new auxiliary data (aux_data) node
 * 
 * Allocates and initializes an `rr_aux_data_t` structure for storing additional
 * syscall information (e.g., read buffers, mmap parameter structures).
 * 
 * @param kind Data type (AUX_BUFFER, AUX_STRUCT, AUX_SCALAR, etc.)
 * @param arg_mask Argument mask (1 << arg_index) indicating the associated argument
 * @param data Pointer to source data (deep-copied into the newly allocated buffer)
 * @param size Data size in bytes
 * 
 * @return rr_aux_data_t* 
 *         - Pointer to the newly created node
 *         - NULL if parameters are invalid or memory allocation fails
 * 
 * @note Performs a memory copy. Consider external storage for large data (> 64KB).
 * @note Global statistics (g_aux_stats) are updated automatically.
 */
rr_aux_data_t *rr_aux_create(rr_aux_kind_t kind, uint8_t arg_mask, 
                             const void *data, uint32_t size);

/**
 * Add aux data to a list (chain multiple entries)
 */
void rr_aux_append(rr_aux_data_t **list, rr_aux_data_t *entry);

/**
 * Find aux data for specific argument
 */
/**
 * @brief Find auxiliary data for a specific argument in the list
 * 
 * Searches for an aux_data entry based on its arg_mask.
 * 
 * @param list Pointer to the head of the aux list
 * @param arg_mask Argument mask to search for
 * 
 * @return rr_aux_data_t* 
 *         - Pointer to the found node
 *         - NULL if not found
 * 
 * @note Typically, there is only one aux_data entry per argument index.
 */
rr_aux_data_t *rr_aux_find(rr_aux_data_t *list, uint8_t arg_mask);

/**
 * Free aux data list
 */
void rr_aux_free(rr_aux_data_t *list);

/**
 * Check if data should be recorded (size heuristic)
 */
/**
 * @brief Determine if auxiliary data should be recorded (intelligent heuristic)
 * 
 * Heuristic function to decide whether to record data, preventing trace bloat.
 * 
 * **Decision Strategy**:
 * 1. **Small Data (<= 4KB)**: Always record (Rule 1)
 * 2. **Medium Data (4KB - 64KB)**: Selective recording (Rule 2)
 *    - Standard streams (stdin, stdout, stderr): Record
 *    - Critical Syscalls (read, write, getrandom): Record
 *    - Network I/O: Record
 *    - Others: Record only if <= 16KB
 * 3. **Large Data (> 64KB)**: Skip (Rule 3)
 *    - Avoid performance issues and excessively large trace files.
 * 
 * @param size Data size in bytes
 * @param fd Associated file descriptor (if applicable)
 * @param syscall_nr Syscall number
 * 
 * @return true if data should be recorded
 * @return false if recording should be skipped (replay will rely on environment or re-execution)
 * 
 * @note Critical non-deterministic calls like getrandom may be forcefully recorded.
 * @warning Skipping data decreases determinism by making replay environment-dependent (Hybrid mode).
 * @todo Implement external storage support for recording large datasets.
 */
bool rr_aux_should_record(uint32_t size, int fd, int syscall_nr);

/**
 * Serialize aux data to external file (for large data)
 */
int rr_aux_save_external(rr_aux_data_t *aux, const char *base_path, int record_id);

/**
 * Load aux data from external file
 */
int rr_aux_load_external(rr_aux_data_t *aux);

/**
 * Serialize aux data to trace line
 * Format: "  AUX[arg]: kind=BUFFER, size=832, data=<base64>"
 */
void rr_aux_serialize_to_trace(rr_aux_data_t *aux, FILE *trace_file);

/**
 * Parse aux data from trace line
 */
rr_aux_data_t *rr_aux_parse_from_trace(const char *line);

/* Statistics */
typedef struct {
    uint64_t total_aux_entries;
    uint64_t total_bytes_inline;
    uint64_t total_bytes_external;
    uint64_t buffers_recorded;
    uint64_t buffers_skipped;
} rr_aux_stats_t;

extern rr_aux_stats_t g_aux_stats;

void rr_aux_print_stats(void);

#endif /* RR_AUX_DATA_H */

