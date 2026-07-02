/**
 * RR-Fuzz Auxiliary Data System Implementation
 * 
 * Inspired by EnvFuzz's AUX system for pure deterministic replay.
 * This module handles recording and replaying of buffer contents,
 * structures, and other data associated with syscall arguments.
 */

#include "rr_aux_data.h"
#include "rr_framework.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* Global statistics */
rr_aux_stats_t g_aux_stats = {0};

/**
 * Create a new auxiliary data entry
 */
/**
 * @brief Create a new auxiliary data (aux_data) node
 * 
 * Allocates and initializes an `rr_aux_data_t` structure to store additional
 * syscall information (e.g., buffer contents from read, mmap parameter structures).
 * 
 * @param kind Data type (AUX_BUFFER, AUX_STRUCT, AUX_SCALAR, etc.)
 * @param arg_mask Argument mask (1 << arg_index) indicating which argument this data relates to
 * @param data Pointer to source data (deep-copied into the newly allocated buffer)
 * @param size Data size in bytes
 * 
 * @return rr_aux_data_t* 
 *         - Pointer to the newly created node
 *         - NULL if parameters are invalid or memory allocation fails
 * 
 * @note This function performs a memory copy. Consider external storage for very large data (>64KB).
 * @note Global statistics (g_aux_stats) are automatically updated.
 */
rr_aux_data_t *rr_aux_create(rr_aux_kind_t kind, uint8_t arg_mask, 
                             const void *data, uint32_t size)
{
    if (!data || size == 0) {
        return NULL;
    }

    rr_aux_data_t *aux = g_malloc0(sizeof(rr_aux_data_t));
    if (!aux) {
        RR_ERROR("Failed to allocate aux data entry");
        return NULL;
    }

    aux->kind = kind;
    aux->arg_mask = arg_mask;
    aux->size = size;
    aux->next = NULL;
    aux->is_external = false;
    aux->external_file = NULL;

    /* Allocate and copy data */
    aux->data = g_malloc(size);
    if (!aux->data) {
        RR_ERROR("Failed to allocate aux data buffer (%u bytes)", size);
        g_free(aux);
        return NULL;
    }

    memcpy(aux->data, data, size);

    /* Update statistics */
    g_aux_stats.total_aux_entries++;
    g_aux_stats.total_bytes_inline += size;
    g_aux_stats.buffers_recorded++;

    RR_VERBOSE("Created aux data: kind=%d, arg=%d, size=%u", kind, arg_mask, size);
    return aux;
}

/**
 * Add aux data to a list (chain multiple entries)
 */
void rr_aux_append(rr_aux_data_t **list, rr_aux_data_t *entry)
{
    if (!list || !entry) {
        return;
    }

    if (*list == NULL) {
        *list = entry;
    } else {
        rr_aux_data_t *curr = *list;
        while (curr->next) {
            curr = curr->next;
        }
        curr->next = entry;
    }
}

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
rr_aux_data_t *rr_aux_find(rr_aux_data_t *list, uint8_t arg_mask)
{
    rr_aux_data_t *curr = list;
    while (curr) {
        if (curr->arg_mask == arg_mask) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/**
 * Free aux data list
 */
void rr_aux_free(rr_aux_data_t *list)
{
    rr_aux_data_t *curr = list;
    while (curr) {
        rr_aux_data_t *next = curr->next;
        
        if (curr->data) {
            g_free(curr->data);
        }
        if (curr->external_file) {
            g_free(curr->external_file);
        }
        g_free(curr);
        
        curr = next;
    }
}

/**
 * Check if data should be recorded (size heuristic)
 * 
 * Strategy:
 * - Small data (<= 4KB): Always record
 * - Medium data (4KB - 64KB): Selective based on FD type
 * - Large data (> 64KB): Skip (fallback to hybrid mode)
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
 */
bool rr_aux_should_record(uint32_t size, int fd, int syscall_nr)
{
    /* Rule 1: Always record small data */
    if (size <= AUX_MAX_INLINE_SIZE) {
        return true;
    }

    /* Rule 2: Medium data - selective recording */
    if (size <= AUX_MAX_RECORD_SIZE) {
        /* For file I/O, be more selective */
        if (fd >= 0 && fd <= 2) {
            /* Always record stdin/stdout/stderr */
            return true;
        }
        
        /* For regular files, record based on syscall type */
        switch (syscall_nr) {
            case TARGET_NR_read:
            case TARGET_NR_write:
#ifdef TARGET_NR_pread64
            case TARGET_NR_pread64:
#endif
#ifdef TARGET_NR_pwrite64
            case TARGET_NR_pwrite64:
#endif
                /* Record I/O operations */
                return true;
            
            case TARGET_NR_getrandom:
                /* Always record random data for determinism */
                return true;
            
#ifdef TARGET_NR_sendto
            case TARGET_NR_sendto:
#endif
#ifdef TARGET_NR_recvfrom
            case TARGET_NR_recvfrom:
#endif
#ifdef TARGET_NR_sendmsg
            case TARGET_NR_sendmsg:
#endif
#ifdef TARGET_NR_recvmsg
            case TARGET_NR_recvmsg:
#endif
                /* Record network I/O operations */
                return true;
            
            default:
                /* For other syscalls, be conservative */
                return size <= 16 * 1024; /* 16KB threshold */
        }
    }

    /* Rule 3: Skip large data */
    g_aux_stats.buffers_skipped++;
    RR_VERBOSE("Skipping large data: size=%u, fd=%d, syscall=%d", size, fd, syscall_nr);
    return false;
}

/**
 * Serialize aux data to external file (for large data)
 */
int rr_aux_save_external(rr_aux_data_t *aux, const char *base_path, int record_id)
{
    if (!aux || !base_path) {
        return -EINVAL;
    }

    /* Generate external file name */
    char filename[512];
    snprintf(filename, sizeof(filename), "%s_data/record_%06d_arg%d.bin",
             base_path, record_id, aux->arg_mask);

    FILE *f = fopen(filename, "wb");
    if (!f) {
        RR_ERROR("Failed to open external data file: %s", filename);
        return -errno;
    }

    size_t written = fwrite(aux->data, 1, aux->size, f);
    fclose(f);

    if (written != aux->size) {
        RR_ERROR("Failed to write complete aux data to external file");
        return -EIO;
    }

    /* Update aux entry */
    aux->is_external = true;
    aux->external_file = g_strdup(filename);
    
    /* Free inline data to save memory */
    g_free(aux->data);
    aux->data = NULL;

    /* Update statistics */
    g_aux_stats.total_bytes_external += aux->size;
    g_aux_stats.total_bytes_inline -= aux->size;

    RR_VERBOSE("Saved aux data to external file: %s (%u bytes)", filename, aux->size);
    return 0;
}

/**
 * Load aux data from external file
 */
int rr_aux_load_external(rr_aux_data_t *aux)
{
    if (!aux || !aux->is_external || !aux->external_file) {
        return -EINVAL;
    }

    FILE *f = fopen(aux->external_file, "rb");
    if (!f) {
        RR_ERROR("Failed to open external data file: %s", aux->external_file);
        return -errno;
    }

    /* Allocate buffer */
    aux->data = g_malloc(aux->size);
    if (!aux->data) {
        fclose(f);
        return -ENOMEM;
    }

    /* Read data */
    size_t read_bytes = fread(aux->data, 1, aux->size, f);
    fclose(f);

    if (read_bytes != aux->size) {
        RR_ERROR("Failed to read complete aux data from external file");
        g_free(aux->data);
        aux->data = NULL;
        return -EIO;
    }

    RR_VERBOSE("Loaded aux data from external file: %s (%u bytes)", 
               aux->external_file, aux->size);
    return 0;
}

/**
 * Serialize aux data to trace line
 * Format: "  AUX[arg]: kind=BUFFER, size=832, data=<hex or file>"
 */
void rr_aux_serialize_to_trace(rr_aux_data_t *aux, FILE *trace_file)
{
    if (!aux || !trace_file) {
        return;
    }

    const char *kind_str;
    switch (aux->kind) {
        case AUX_BUFFER: kind_str = "BUFFER"; break;
        case AUX_STRING: kind_str = "STRING"; break;
        case AUX_IOV: kind_str = "IOV"; break;
        case AUX_MSG: kind_str = "MSG"; break;
        case AUX_STAT: kind_str = "STAT"; break;
        case AUX_TIMEVAL: kind_str = "TIMEVAL"; break;
        case AUX_TIMESPEC: kind_str = "TIMESPEC"; break;
        case AUX_POLLFD: kind_str = "POLLFD"; break;
        case AUX_FDSET: kind_str = "FDSET"; break;
        case AUX_MMAP_CONTENT: kind_str = "MMAP_CONTENT"; break;
        default: kind_str = "UNKNOWN"; break;
    }

    fprintf(trace_file, "  AUX[%d]: kind=%s, size=%u", 
            aux->arg_mask, kind_str, aux->size);

    if (aux->is_external) {
        fprintf(trace_file, ", file=%s\n", aux->external_file);
    } else if (aux->size <= 64) {
        /* Inline small data as hex */
        fprintf(trace_file, ", data=");
        for (uint32_t i = 0; i < aux->size; i++) {
            fprintf(trace_file, "%02x", aux->data[i]);
        }
        fprintf(trace_file, "\n");
    } else {
        fprintf(trace_file, ", data=<inline:%u bytes>\n", aux->size);
    }
}

/**
 * Parse aux data from trace line
 * Expected format: "  AUX[N]: kind=TYPE, size=SIZE, data=HEX"
 */
rr_aux_data_t *rr_aux_parse_from_trace(const char *line)
{
    if (!line || strncmp(line, "  AUX[", 6) != 0) {
        return NULL;
    }

    rr_aux_data_t *aux = g_malloc0(sizeof(rr_aux_data_t));
    
    /* Parse arg mask */
    int arg;
    if (sscanf(line, "  AUX[%d]:", &arg) != 1) {
        g_free(aux);
        return NULL;
    }
    aux->arg_mask = (uint8_t)arg;

    /* Parse kind */
    char kind_str[32];
    if (sscanf(line, "  AUX[%*d]: kind=%31[^,]", kind_str) == 1) {
        if (strcmp(kind_str, "BUFFER") == 0) aux->kind = AUX_BUFFER;
        else if (strcmp(kind_str, "STRING") == 0) aux->kind = AUX_STRING;
        else if (strcmp(kind_str, "IOV") == 0) aux->kind = AUX_IOV;
        else if (strcmp(kind_str, "MSG") == 0) aux->kind = AUX_MSG;
        else if (strcmp(kind_str, "STAT") == 0) aux->kind = AUX_STAT;
        else if (strcmp(kind_str, "TIMEVAL") == 0) aux->kind = AUX_TIMEVAL;
        else if (strcmp(kind_str, "TIMESPEC") == 0) aux->kind = AUX_TIMESPEC;
        else if (strcmp(kind_str, "POLLFD") == 0) aux->kind = AUX_POLLFD;
        else if (strcmp(kind_str, "FDSET") == 0) aux->kind = AUX_FDSET;
        else if (strcmp(kind_str, "MMAP_CONTENT") == 0) aux->kind = AUX_MMAP_CONTENT;
    }

    /* Parse size */
    if (sscanf(line, "  AUX[%*d]: kind=%*[^,], size=%u", &aux->size) != 1) {
        g_free(aux);
        return NULL;
    }

    /* Check if external file */
    const char *file_marker = strstr(line, "file=");
    if (file_marker) {
        char filename[256];
        if (sscanf(file_marker, "file=%255s", filename) == 1) {
            aux->is_external = true;
            aux->external_file = g_strdup(filename);
            aux->data = NULL; /* Will be loaded on demand */
        }
    } else {
        /* Parse inline hex data */
        const char *data_marker = strstr(line, "data=");
        if (data_marker && aux->size > 0) {
            data_marker += 5; /* Skip "data=" */
            aux->data = g_malloc(aux->size);
            
            for (uint32_t i = 0; i < aux->size && data_marker[i*2]; i++) {
                unsigned int byte;
                if (sscanf(&data_marker[i*2], "%2x", &byte) == 1) {
                    aux->data[i] = (uint8_t)byte;
                }
            }
        }
    }

    return aux;
}

/**
 * Print statistics
 */
void rr_aux_print_stats(void)
{
    fprintf(stderr, "\n=== AUX Data Statistics ===\n");
    fprintf(stderr, "Total entries:       %lu\n", g_aux_stats.total_aux_entries);
    fprintf(stderr, "Buffers recorded:    %lu\n", g_aux_stats.buffers_recorded);
    fprintf(stderr, "Buffers skipped:     %lu\n", g_aux_stats.buffers_skipped);
    fprintf(stderr, "Inline bytes:        %lu (%.2f KB)\n", 
            g_aux_stats.total_bytes_inline,
            g_aux_stats.total_bytes_inline / 1024.0);
    fprintf(stderr, "External bytes:      %lu (%.2f KB)\n",
            g_aux_stats.total_bytes_external,
            g_aux_stats.total_bytes_external / 1024.0);
    fprintf(stderr, "Total bytes:         %lu (%.2f KB)\n",
            g_aux_stats.total_bytes_inline + g_aux_stats.total_bytes_external,
            (g_aux_stats.total_bytes_inline + g_aux_stats.total_bytes_external) / 1024.0);
    fprintf(stderr, "===========================\n\n");
}
