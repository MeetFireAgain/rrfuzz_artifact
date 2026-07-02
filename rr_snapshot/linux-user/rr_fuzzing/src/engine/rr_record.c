/**
 * RR-Fuzz Recording Module
 * Implements system call recording logic for Record mode.
 */

#define RR_DEBUG 1

#include "rr_framework.h"
#include "rr_bb_trace.h"
#include "rr_aux_data.h"
#include "rr_syscall_dispatch.h"
#include "rr_constants.h"
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

static FILE *g_trace_file = NULL;
/* Global written counter to ensure valid 0-based indexing on file write */
static uint32_t g_written_count = 0;

static rr_aux_data_t *record_aux_scalar(uint8_t mask, const abi_long *value)
{
    abi_long val = value ? *value : 0;
    return rr_aux_create(AUX_SCALAR, mask, &val, sizeof(val));
}

/**
 * Helper function: Convert arg_data to aux_data (used for fuzzing)
 * @param record: syscall record
 * @param arg_index: argument index (0-7)
 * @param data: data pointer (if NULL, use record->arg_data[arg_index])
 * @param size: data size (if 0, use record->arg_size[arg_index])
 * @return: true on success, false on failure
 */
static bool rr_promote_arg_to_aux(syscall_record_t *record, int arg_index, 
                                   const uint8_t *data, size_t size)
{
    if (!record || arg_index < 0 || arg_index >= RR_MAX_SYSCALL_ARGS) {
        return false;
    }
    
    /* If no data provided, try using arg_data */
    if (!data) {
        data = record->arg_data[arg_index];
        if (!data) return false;
    }
    
    /* If no size provided, try using arg_size */
    if (size == 0) {
        size = record->arg_size[arg_index];
        if (size == 0) return false;
    }
    
    /* Create aux_data */
    uint8_t *aux_data_copy = g_malloc(size);
    if (!aux_data_copy) return false;
    
    memcpy(aux_data_copy, data, size);
    
    rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, (1 << arg_index), 
                                       aux_data_copy, size);
    if (!aux) {
        g_free(aux_data_copy);
        return false;
    }
    
    /* Add to aux_data list */
    rr_aux_append(&record->aux_data, aux);
    record->has_aux_data = true;
    
    return true;
}

/**
 * Disposes of a syscall_record_t and its associated data
 */
void rr_record_dispose(syscall_record_t *record)
{
    if (!record) {
        return;
    }

    /* Free all arg_data */
    for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
        if (record->arg_data[i]) {
            g_free(record->arg_data[i]);
            record->arg_data[i] = NULL;
        }
    }

    /* Free aux_data list */
    if (record->aux_data) {
        rr_aux_free(record->aux_data);
        record->aux_data = NULL;
    }

    /* Free record itself */
    g_free(record);
}

/**
 * @brief Initializes Record mode and opens the trace file for syscall recording.
 * 
 * This function serves as the entry point for RR-Fuzz Record mode. It is responsible for:
 * 1. Opening the binary trace file (.dat format).
 * 2. Writing the trace file header (including magic and version).
 * 3. Initializing the Basic Block (BB) trace subsystem.
 * 
 * **Trace File Format**:
 * ```
 * Header: [magic=0x52525254 ("RRTR")][version=1][record_count (placeholder)]
 * Body:   [syscall_record_1][syscall_record_2]...[syscall_record_N]
 * ```
 * 
 * @param trace_file Path to the trace file. If NULL, defaults to "rr_trace.dat".
 * 
 * @return int
 *         - 0: Initialization successful; trace file opened and header written.
 *         - -1: Initialization failed (e.g., file cannot be opened).
 * 
 * @note This function should be called exactly once (within rr_framework_init).
 * @note The trace file uses a binary format and is not directly viewable in local text editors.
 * @note record_count in the header is a placeholder; it is updated with the actual count in rr_stop_recording().
 * @note Failure to initialize BB trace does not fail the entire process; a warning is logged instead.
 * 
 * @warning Existing trace files will be overwritten ("wb" mode).
 * @warning Ensure rr_stop_recording() is called before process exit to correctly update the header.
 * 
 * @see rr_stop_recording() for closing the trace and updating metadata.
 * @see rr_record_syscall() for writing individual syscalls.
 * @see rr_bb_trace_init() for BB trace initialization.
 */
int rr_start_recording(const char *trace_file)
{
    RR_VERBOSE("Starting recording initialization");

    if (!trace_file) {
        trace_file = "rr_trace.dat";
        RR_INFO("Using default trace file: %s", trace_file);
    }

    RR_INFO("Opening trace file for writing: %s", trace_file);
    g_trace_file = fopen(trace_file, "wb");
    if (!g_trace_file) {
        RR_ERROR("Failed to open trace file: %s", trace_file);
        return -1;
    }

    if (g_rr_framework) {
        g_rr_framework->trace_length = 0;
    }
    g_written_count = 0;

    /* Write file header - Always Little Endian */
    uint32_t magic = cpu_to_le32(0x52525254); // "RRTR"
    uint32_t version = cpu_to_le32(1);
    uint32_t placeholder_count = 0; // Placeholder, updated at end
    RR_VERBOSE("Writing trace file header: magic=0x%x, version=%u", 0x52525254, 1);
    fwrite(&magic, sizeof(magic), 1, g_trace_file);
    fwrite(&version, sizeof(version), 1, g_trace_file);
    fwrite(&placeholder_count, sizeof(placeholder_count), 1, g_trace_file);


    /* Initialize BB trace */
    if (rr_bb_trace_init(trace_file) < 0) {
        RR_WARN("Failed to initialize BB trace (continuing without BB trace)");
    } else {
        RR_INFO("BB trace initialized successfully");
    }
    RR_INFO("Recording started successfully to: %s", trace_file);
    return 0;
}


/**
 * Stop recording
 */
void rr_stop_recording(void)
{
    /* Cleanup BB trace */
    rr_bb_trace_cleanup();
    
    if (g_trace_file) {
        RR_VERBOSE("STOP_RECORDING: Finalizing trace file");

        /* Get file size */
        fseek(g_trace_file, 0, SEEK_END);
        long file_size = ftell(g_trace_file);

        /* Write trace length to file header - Always Little Endian */
        uint32_t record_count = g_rr_framework ? g_rr_framework->trace_length : 0;
        uint32_t le_record_count = cpu_to_le32(record_count);
        RR_VERBOSE("STOP_RECORDING: Updating header with record_count=%u, file_size=%ld", record_count, file_size);

        fseek(g_trace_file, sizeof(uint32_t) * 2, SEEK_SET);  // Skip magic and version
        size_t written = fwrite(&le_record_count, sizeof(le_record_count), 1, g_trace_file);
        if (written != 1) {
            RR_ERROR("STOP_RECORDING: Failed to write record count to header");
        } else {
            RR_VERBOSE("STOP_RECORDING: Successfully wrote record_count=%u to header", record_count);
        }

        fflush(g_trace_file);
        fclose(g_trace_file);
        g_trace_file = NULL;

        RR_INFO("Recording stopped: %u syscalls recorded, %ld bytes written", record_count, file_size);
    } else {
        RR_VERBOSE("STOP_RECORDING: Recording stop called but no trace file was open");
    }
}

/**
 * Captures string parameter data (dereferences pointer arguments)
 */
uint8_t *rr_capture_string(CPUArchState *env, target_ulong addr, size_t *len)
{
    if (addr == 0) {
        *len = 0;
        return NULL;
    }

    /* Use target_strlen to get string length */
    size_t str_len = 0;
    target_ulong current = addr;

    /* Simple implementation: read byte-by-byte until \0, up to RR_MAX_PATH_LENGTH bytes */
    while (str_len < RR_MAX_PATH_LENGTH) {
        uint8_t byte;
        if (cpu_memory_rw_debug(env_cpu(env), current, &byte, 1, 0) != 0) {
            break;
        }
        if (byte == 0) {
            break;
        }
        str_len++;
        current++;
    }

    if (str_len == 0) {
        *len = 0;
        return NULL;
    }

    /* Allocate and read full string (including \0) */
    uint8_t *data = g_malloc(str_len + 1);
    if (cpu_memory_rw_debug(env_cpu(env), addr, data, str_len + 1, 0) != 0) {
        g_free(data);
        *len = 0;
        return NULL;
    }

    *len = str_len + 1;
    return data;
}

/**
 * Captures buffer parameter data
 */
uint8_t *rr_capture_buffer(CPUArchState *env, target_ulong addr, size_t size)
{
    if (addr == 0 || size == 0 || size > RR_MAX_BUFFER_TOTAL) {
        return NULL;
    }

    uint8_t *data = g_malloc(size);
    if (cpu_memory_rw_debug(env_cpu(env), addr, data, size, 0) != 0) {
        g_free(data);
        return NULL;
    }

    return data;
}

/**
 * Detects if a syscall creates an FD
 */
static bool syscall_creates_fd(int syscall_nr, abi_long ret)
{
    if (ret < 0) {
        return false;
    }

    switch (syscall_nr) {
#ifdef TARGET_NR_open
        case TARGET_NR_open:
#endif
        case TARGET_NR_openat:
#ifdef TARGET_NR_creat
        case TARGET_NR_creat:
#endif
        case TARGET_NR_socket:
#ifdef TARGET_NR_pipe
        case TARGET_NR_pipe:
#endif
#ifdef TARGET_NR_pipe2
        case TARGET_NR_pipe2:
#endif
        case TARGET_NR_dup:
#ifdef TARGET_NR_dup2
        case TARGET_NR_dup2:
#endif
#ifdef TARGET_NR_dup3
        case TARGET_NR_dup3:
#endif
            return true;
        default:
            return false;
    }
}

/**
 * Smartly captures syscall parameter data using aux_data system
 * 
 * Recommended capture method: automatically captures key data based on syscall type.
 * Supports external storage for large data and threshold-based skipping.
 * 
 * Capture Strategy (by priority):
 * 1. Non-deterministic data: getrandom (Critical!)
 * 2. I/O data: read/write (Subject to rr_aux_should_record thresholds)
 * 3. Memory management: mmap/brk/munmap/mprotect (Records addresses and params)
 * 4. Process management: fork/clone (Records returned PID)
 * 5. Network data: recv/send series (Subject to size limits)
 * 6. ioctl: Capture output buffer based on command
 * 
 * aux_data types:
 * - AUX_BUFFER: Byte array (e.g., read/write buffer)
 * - AUX_STRUCT: Structure (e.g., mmap_info, mm_params)
 * - AUX_SCALAR: Scalar value (e.g., brk return address)
 *
 * @param env CPU architecture state pointer (for reading guest memory).
 * @param syscall_nr Syscall number.
 * @param args Syscall arguments array (8 arguments).
 * @param ret Syscall return value.
 * @param record Syscall record structure; captured aux_data is added to record->aux_data list.
 * 
 * @note Automatically sets record->has_aux_data = true if any data is captured.
 * @note Uses smart thresholds: <= 4KB always capture, 4KB-64KB partial capture, > 64KB skip.
 * @note getrandom data is always captured regardless of size (critical for deterministic replay).
 * 
 * @warning If use_legacy_capture is also enabled, it will double-capture with capture_syscall_args().
 * @warning Output syscalls (write/send) data is not used during replay (requires real execution).
 * 
 * @see rr_aux_create() Create aux_data node.
 * @see rr_aux_append() Append aux_data to list.
 * @see rr_aux_should_record() Policy for determining if data should be recorded.
 * @see rr_capture_buffer() Read buffer from guest memory.
 * @see rr_record_syscall() Location where this function is called.
 */
static void capture_syscall_args_aux(CPUArchState *env, int syscall_nr,
                                    const abi_long *args, abi_long ret, syscall_record_t *record)
{
    /* Automatically capture key data using smart threshold control */

    switch (syscall_nr) {
        case TARGET_NR_brk: {
            /* Record new heap top address returned by brk */
            if (ret > 0) {
                rr_aux_data_t *aux = record_aux_scalar(0, &ret);
                if (aux) {
                    rr_aux_append(&record->aux_data, aux);
                    record->has_aux_data = true;
                }
            }
            break;
        }

#if defined(TARGET_NR_mmap)
        case TARGET_NR_mmap:
#endif
#if defined(TARGET_NR_mmap2)
        case TARGET_NR_mmap2:
#endif
        {
            if (ret != (abi_long)-1) {
                rr_aux_mmap_info_t info = {
                    .addr = (uint64_t)ret,
                    .length = (uint64_t)args[1],
                    .prot = (int64_t)args[2],
                    .flags = (int64_t)args[3],
                    .fd = (int64_t)args[4],
                    .offset = (uint64_t)args[5],
                };
                rr_aux_data_t *aux = rr_aux_create(AUX_STRUCT, 0, &info, sizeof(info));
                if (aux) {
                    rr_aux_append(&record->aux_data, aux);
                    record->has_aux_data = true;
                }
            }
            break;
        }

        case TARGET_NR_munmap:
        case TARGET_NR_mprotect:
        case TARGET_NR_mremap:
        case TARGET_NR_madvise: {
            /* Record memory management parameters for replay validation */
            rr_aux_mm_params_t mm_aux = {
                .addr = (uint64_t)args[0],
                .len = (uint64_t)args[1],
                .extra1 = (int64_t)args[2],
                .extra2 = (int64_t)args[3],
            };
            rr_aux_data_t *aux = rr_aux_create(AUX_STRUCT, 0, &mm_aux, sizeof(mm_aux));
            if (aux) {
                rr_aux_append(&record->aux_data, aux);
                record->has_aux_data = true;
            }
            break;
        }

        case TARGET_NR_clone:
#ifdef TARGET_NR_fork
        case TARGET_NR_fork:
#endif
#ifdef TARGET_NR_vfork
        case TARGET_NR_vfork:
#endif
        {
            if (ret > 0) {
                rr_aux_data_t *aux = record_aux_scalar(0, &ret);
                if (aux) {
                    rr_aux_append(&record->aux_data, aux);
                    record->has_aux_data = true;
                }
            }
            break;
        }

        case TARGET_NR_read:
            /* read data is only valid after the call returns */
            if (ret > 0 && args[1] != 0) {
                if (rr_aux_should_record(ret, args[0], syscall_nr)) {
                    uint8_t *data = rr_capture_buffer(env, args[1], ret);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, ret);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                        }
                        g_free(data);
                    }
                }
            }
            break;

        case TARGET_NR_write:
            /* write data exists before the call */
            if (args[2] > 0 && args[1] != 0) {
                if (rr_aux_should_record(args[2], args[0], syscall_nr)) {
                    uint8_t *data = rr_capture_buffer(env, args[1], args[2]);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, args[2]);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                        }
                        g_free(data);
                    }
                }
            }
            break;

#ifdef TARGET_NR_getrandom
        case TARGET_NR_getrandom:
#else
        case 318: /* x86_64 getrandom */
#endif
            /* Critical non-deterministic call - always record */
            RR_VERBOSE("AUX_CAPTURE: getrandom ret=%ld, args[0]=0x%lx", (long)ret, (unsigned long)args[0]);
            if (ret > 0 && args[0] != 0) {
                uint8_t *data = rr_capture_buffer(env, args[0], ret);
                RR_VERBOSE("AUX_CAPTURE: rr_capture_buffer returned %p, size=%ld", data, (long)ret);
                if (data) {
                    rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 0, data, ret);
                    RR_VERBOSE("AUX_CAPTURE: rr_aux_create returned %p", aux);
                    if (aux) {
                        rr_aux_append(&record->aux_data, aux);
                        record->has_aux_data = true;
                        RR_VERBOSE("AUX_CAPTURE: Successfully created aux_data for getrandom, size=%ld", (long)ret);
                    }
                    g_free(data);
                }
            }
            break;

#ifdef TARGET_NR_openat
        case TARGET_NR_openat:
            /* Capture file path */
            if (args[1] != 0) {
                size_t len;
                uint8_t *data = rr_capture_string(env, args[1], &len);
                if (data && len > 0) {
                    rr_aux_data_t *aux = rr_aux_create(AUX_STRING, 1, data, len);
                    if (aux) {
                        rr_aux_append(&record->aux_data, aux);
                        record->has_aux_data = true;
                    }
                    g_free(data);
                }
            }
            break;
#endif

#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64:
            if (ret > 0 && args[1] != 0) {
                if (rr_aux_should_record(ret, args[0], syscall_nr)) {
                    uint8_t *data = rr_capture_buffer(env, args[1], ret);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, ret);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                        }
                        g_free(data);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_sendto
        case TARGET_NR_sendto:
            /* sendto data exists before the call (like write) */
            RR_VERBOSE("AUX_CAPTURE: sendto - args[2]=%ld, args[1]=0x%lx, args[0]=%d", (long)args[2], (unsigned long)args[1], (int)args[0]);
            if (args[2] > 0 && args[1] != 0 && args[2] <= RR_MAX_BUFFER_TOTAL) {
                bool should_record = rr_aux_should_record(args[2], args[0], syscall_nr);
                RR_VERBOSE("AUX_CAPTURE: rr_aux_should_record returned %d for sendto (size=%ld, fd=%d)", should_record, (long)args[2], (int)args[0]);
                if (should_record) {
                    uint8_t *data = rr_capture_buffer(env, args[1], args[2]);
                    RR_VERBOSE("AUX_CAPTURE: rr_capture_buffer returned %p", data);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, args[2]);
                        RR_VERBOSE("AUX_CAPTURE: rr_aux_create returned %p", aux);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                            RR_VERBOSE("AUX_CAPTURE: Successfully created aux_data for sendto, size=%ld", (long)args[2]);
                        }
                        g_free(data);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
            /* Capture received data */
            if (ret > 0 && args[1] != 0) {
                if (rr_aux_should_record(ret, args[0], syscall_nr)) {
                    uint8_t *data = rr_capture_buffer(env, args[1], ret);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, ret);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                        }
                        g_free(data);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_accept
        #ifdef TARGET_NR_accept
        case TARGET_NR_accept:
#endif
#endif
#ifdef TARGET_NR_accept4
        case TARGET_NR_accept4:
#endif
#ifdef TARGET_NR_getsockname
        case TARGET_NR_getsockname:
#endif
#ifdef TARGET_NR_getpeername
        case TARGET_NR_getpeername:
#endif
            /* Capture sockaddr structure (arg 1) */
            if (ret >= 0 && args[1] != 0 && args[2] != 0) {
                uint32_t addr_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[2], (uint8_t*)&addr_len, sizeof(uint32_t), 0) == 0) {
                    if (addr_len > 0 && addr_len <= 128) {
                        uint8_t *data = rr_capture_buffer(env, args[1], addr_len);
                        if (data) {
                            rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, addr_len);
                            if (aux) {
                                rr_aux_append(&record->aux_data, aux);
                                record->has_aux_data = true;
                                RR_VERBOSE("RR-NETWORK: Captured %u bytes sockaddr for syscall %d", addr_len, syscall_nr);
                            }
                            g_free(data);
                        }
                    }
                }
            }
            break;

#ifdef TARGET_NR_bind
        case TARGET_NR_bind:
#endif
#ifdef TARGET_NR_listen
        case TARGET_NR_listen:
#endif
#ifdef TARGET_NR_setsockopt
        case TARGET_NR_setsockopt:
#endif
            /* These don't return data in buffers, but we mark them as having aux_data
             * to trigger Pure Replay (which will just return the recorded retval).
             */
            record->has_aux_data = true;
            RR_VERBOSE("RR-NETWORK: Marked syscall %d as having aux_data for pure replay", syscall_nr);
            break;

#ifdef TARGET_NR_socketcall
        case TARGET_NR_socketcall: {
            /* For socketcall, marking it as having aux_data triggers pure replay path.
             * This allows the replayer to return recorded results instead of executing natively.
             */
            record->has_aux_data = true;
            RR_VERBOSE("RR-NETWORK: Marked socketcall (call=%ld) as having aux_data", (long)args[0]);
            break;
        }
#endif
        default:
            /* Other syscalls do not support aux_data yet */
            break;
    }
}

/**
 * Smartly captures syscall parameter data (Legacy method - kept for backward compatibility)
 */
static void capture_syscall_args(CPUArchState *env, int syscall_nr,
                                 const abi_long *args, abi_long ret, syscall_record_t *record)
{
    switch (syscall_nr) {
#ifdef TARGET_NR_open
        case TARGET_NR_open:
#endif
        case TARGET_NR_openat:
            /* Path string (first arg or second for openat) */
#ifdef TARGET_NR_open
            if (syscall_nr == TARGET_NR_openat) {
#else
            if (true) {  /* openat is always available */
#endif
                record->arg_data[1] = rr_capture_string(env, args[1], &record->arg_size[1]);
            } else {
                record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            }
            break;

        /* TARGET_NR_read is already handled in capture_syscall_args_aux (after syscall execution) */

        case TARGET_NR_write:
            /* Second arg is data, third is size */
            if (args[2] > 0 && args[2] <= RR_MAX_BUFFER_TOTAL) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                if (record->arg_data[1]) {
                    record->arg_size[1] = args[2];
                    
                    /* 🔥 Add aux_data for fuzzing */
                    rr_promote_arg_to_aux(record, 1, NULL, 0);
                }
            }
            break;

        case TARGET_NR_faccessat:
            /* Second arg is file path string */
            record->arg_data[1] = rr_capture_string(env, args[1], &record->arg_size[1]);
            break;

        case TARGET_NR_execve:
            /* First arg is program path */
            record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            // TODO: Capture argv and envp arrays
            break;

#ifdef TARGET_NR_uname
        case TARGET_NR_uname:
            /* First arg is struct utsname *, captured after syscall returns */
            if (args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], sizeof(struct utsname));
                if (record->arg_data[0]) {
                    record->arg_size[0] = sizeof(struct utsname);
                }
            }
            break;
#endif

#ifdef TARGET_NR_newfstatat
        case TARGET_NR_newfstatat:
#endif
#ifdef TARGET_NR_fstatat64
        case TARGET_NR_fstatat64:
#endif
            /* Second arg is path, third is stat struct */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_string(env, args[1], &record->arg_size[1]);
            }
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], 144); // sizeof(struct stat)
                if (record->arg_data[2]) {
                    record->arg_size[2] = 144;
                }
            }
            break;

        case TARGET_NR_getdents64:
            /* Second arg is directory entries buffer */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_GETDENTS_BUF_SIZE) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                if (record->arg_data[1]) {
                    record->arg_size[1] = args[2];
                }
            }
            break;

#ifdef TARGET_NR_stat
        case TARGET_NR_stat:
            /* First arg is path, second is stat struct */
            record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            if (ret == 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct stat));
                if (record->arg_data[1]) {
                    record->arg_size[1] = sizeof(struct stat);
                }
            }
            break;
#endif

#ifdef TARGET_NR_lstat
        case TARGET_NR_lstat:
            /* First arg is path, second is stat struct */
            record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            if (ret == 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct stat));
                if (record->arg_data[1]) {
                    record->arg_size[1] = sizeof(struct stat);
                }
            }
            break;
#endif

#ifdef TARGET_NR_fstat
        case TARGET_NR_fstat:
            /* Second arg is stat struct */
            if (ret == 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct stat));
                if (record->arg_data[1]) {
                    record->arg_size[1] = sizeof(struct stat);
                }
            }
            break;
#endif

#ifdef TARGET_NR_access
        case TARGET_NR_access:
            /* First arg is path string */
            record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            break;
#endif

#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64:
#endif
#ifdef TARGET_NR_pwrite64
        case TARGET_NR_pwrite64:
#endif
            /* Capture buffer data */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_BUFFER_TOTAL) {
#ifdef TARGET_NR_pread64
                if (syscall_nr == TARGET_NR_pread64 && ret > 0) {
                    /* pread64: capture data after call */
                    record->arg_data[1] = rr_capture_buffer(env, args[1], ret);
                    record->arg_size[1] = ret;
                }
#endif
#ifdef TARGET_NR_pwrite64
                if (syscall_nr == TARGET_NR_pwrite64) {
                    /* pwrite64: capture data before call */
                    record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                    record->arg_size[1] = args[2];
                    
                    /* Add aux_data for fuzzing */
                    rr_promote_arg_to_aux(record, 1, NULL, 0);
                }
#endif
            }
            break;

#ifdef TARGET_NR_gettimeofday
        case TARGET_NR_gettimeofday:
            if (ret == 0 && args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], sizeof(struct timeval));
                if (record->arg_data[0]) {
                    record->arg_size[0] = sizeof(struct timeval);
                    /* Promote to aux_data for Pure Replay */
                    rr_promote_arg_to_aux(record, 0, NULL, 0);
                }
            }
            break;
#endif

#ifdef TARGET_NR_clock_gettime
        case TARGET_NR_clock_gettime:
            if (ret == 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct timespec));
                if (record->arg_data[1]) {
                    record->arg_size[1] = sizeof(struct timespec);
                    /* Promote to aux_data for Pure Replay */
                    rr_promote_arg_to_aux(record, 1, NULL, 0);
                }
            }
            break;
#endif

        // write syscall already handled earlier

        // I/O vector operations
#ifdef TARGET_NR_readv
        case TARGET_NR_readv:
            /* Capture iovec array (simplified: only records the struct array) */
            if (ret > 0 && args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_IOVEC_COUNT) {
                size_t iov_size = sizeof(struct iovec) * args[2];
                record->arg_data[1] = rr_capture_buffer(env, args[1], iov_size);
                record->arg_size[1] = iov_size;
                /* TODO: Full implementation requires iterating each iovec to capture the actual data buffers */
            }
            break;
#endif

#ifdef TARGET_NR_writev
        case TARGET_NR_writev:
            /* Capture iovec array (simplified) */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_IOVEC_COUNT) {
                size_t iov_size = sizeof(struct iovec) * args[2];
                record->arg_data[1] = rr_capture_buffer(env, args[1], iov_size);
                record->arg_size[1] = iov_size;

                /* Add aux_data for fuzzing */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
                /* TODO: Full implementation requires iterating each iovec to capture the actual data buffers */
            }
            break;
#endif

#ifdef TARGET_NR_preadv
        case TARGET_NR_preadv:
            /* preadv = readv + offset */
            if (ret > 0 && args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_IOVEC_COUNT) {
                size_t iov_size = sizeof(struct iovec) * args[2];
                record->arg_data[1] = rr_capture_buffer(env, args[1], iov_size);
                record->arg_size[1] = iov_size;
            }
            break;
#endif

#ifdef TARGET_NR_pwritev
        case TARGET_NR_pwritev:
            /* pwritev = writev + offset */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_IOVEC_COUNT) {
                size_t iov_size = sizeof(struct iovec) * args[2];
                record->arg_data[1] = rr_capture_buffer(env, args[1], iov_size);
                record->arg_size[1] = iov_size;
            }
            break;
#endif

#ifdef TARGET_NR_flock
        case TARGET_NR_flock:
            /* flock parameters are simple (fd, operation), no extra data capture required */
            break;
#endif

        // getrandom - critical non-deterministic call
#ifdef TARGET_NR_getrandom
        case TARGET_NR_getrandom:
#else
        case 318: /* x86_64 getrandom */
#endif
            /* Capture actual random data returned */
            if (ret > 0 && args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], ret);
                record->arg_size[0] = ret;
            }
            break;

        // execve syscall already handled earlier

#ifdef TARGET_NR_wait4
        case TARGET_NR_wait4:
            /* Capture status structure */
            if (ret >= 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(int));
                record->arg_size[1] = sizeof(int);
            }
            break;
#endif

        // Signal handling
#ifdef TARGET_NR_rt_sigaction
        case TARGET_NR_rt_sigaction:
            /* Capture sigaction structure */
            if (args[1] != 0) {
                // New sigaction structure
                record->arg_data[1] = rr_capture_buffer(env, args[1], 152); // sizeof(struct sigaction)
                record->arg_size[1] = 152;
            }
            if (ret == 0 && args[2] != 0) {
                // Old sigaction structure (return value)
                record->arg_data[2] = rr_capture_buffer(env, args[2], 152);
                record->arg_size[2] = 152;
            }
            break;
#endif

#ifdef TARGET_NR_rt_sigprocmask
        case TARGET_NR_rt_sigprocmask:
            /* Capture signal mask */
            if (args[1] != 0) {
                // New signal mask
                record->arg_data[1] = rr_capture_buffer(env, args[1], 8); // sizeof(sigset_t)
                record->arg_size[1] = 8;
            }
            if (ret == 0 && args[2] != 0) {
                // Old signal mask (return value)
                record->arg_data[2] = rr_capture_buffer(env, args[2], 8);
                record->arg_size[2] = 8;
            }
            break;
#endif

        // ioctl - complex device control call
        case TARGET_NR_ioctl:
            /* ioctl parameters are complex and depend on the specific command */
            if (ret == 0 && args[2]) {
                /* For successful ioctl, try to capture output buffer */
                unsigned long cmd = args[1];
                
                        /* Extract ioctl direction and size information */
                /* Linux ioctl encoding: _IOC(dir,type,nr,size) */
                /* dir: _IOC_NONE=0, _IOC_WRITE=1, _IOC_READ=2, _IOC_READ|_IOC_WRITE=3 */
                int ioc_dir = (cmd >> 30) & 0x03;
                int ioc_size = (cmd >> 16) & 0x3FFF;
                
                /* If there is output (_IOC_READ) and it has reasonable size */
                if ((ioc_dir & 2) && ioc_size > 0 && ioc_size < RR_MAX_IOCTL_PAYLOAD) {
                    uint8_t *buf = g_malloc0(ioc_size);
                    if (cpu_memory_rw_debug(env_cpu(env), args[2], buf, ioc_size, 0) == 0) {
                        /* Record output buffer using AUX_IOCTL_OUTPUT type */
                        record->aux_data = rr_aux_create(AUX_IOCTL_OUTPUT, 2, buf, ioc_size);
                        record->has_aux_data = true;
                        RR_VERBOSE("ioctl: Captured %d bytes output buffer for cmd=0x%lx", 
                                   ioc_size, cmd);
                    }
                    g_free(buf);
                } else {
                    RR_VERBOSE("ioctl: cmd=0x%lx, dir=%d, size=%d (not capturing)", 
                               cmd, ioc_dir, ioc_size);
                }
            }
            break;

        // Memory management
#ifdef TARGET_NR_mremap
        case TARGET_NR_mremap:
            /* mremap needs address remapping support */
            // Do not capture parameter data; rely on address remapping mechanism
            break;
#endif

        // Networking syscalls
#ifdef TARGET_NR_socket
        case TARGET_NR_socket:
            /* socket creation, parameters are simple, mainly the returned fd */
            // No need to capture special data; FD mapping mechanism will handle it
            break;
#endif

#ifdef TARGET_NR_connect
        case TARGET_NR_connect:
            /* Capture sockaddr structure */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_SOCKADDR_SIZE) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
            }
            break;
#endif

#ifdef TARGET_NR_accept
        #ifdef TARGET_NR_accept
        case TARGET_NR_accept:
#endif
#endif
#ifdef TARGET_NR_accept4
        case TARGET_NR_accept4:
#endif
            /* Capture sockaddr structure */
            if (ret >= 0 && args[1] != 0 && args[2] != 0) {
                // Read address length first
                uint32_t addr_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[2], (uint8_t*)&addr_len, sizeof(uint32_t), 0) == 0) {
                    if (addr_len > 0 && addr_len <= 128) {
                        record->arg_data[1] = rr_capture_buffer(env, args[1], addr_len);
                        record->arg_size[1] = addr_len;
                        // Also capture address length
                        record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(uint32_t));
                        record->arg_size[2] = sizeof(uint32_t);
                    }
                }
            }
            break;

#ifdef TARGET_NR_sendto
        case TARGET_NR_sendto:
            /* Capture data to be sent and target address */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_BUFFER_TOTAL) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
                
                /* 🔥 Key Fix: Simultaneously create aux_data for fuzzing */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
            }
            if (args[4] != 0 && args[5] > 0 && args[5] <= RR_MAX_SOCKADDR_SIZE) {
                record->arg_data[4] = rr_capture_buffer(env, args[4], args[5]);
                record->arg_size[4] = args[5];
                
                /* Target address can also be fuzzed (optional) */
                rr_promote_arg_to_aux(record, 4, NULL, 0);
            }
            break;
#endif

#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
            /* Capture received data and source address */
            if (ret > 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], ret);
                record->arg_size[1] = ret;
                
                /* Received data can also be used for fuzzing (comparison/mutation during replay) */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
            }
            if (args[4] != 0 && args[5] != 0) {
                // Capture source address and address length
                uint32_t addr_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[5], (uint8_t*)&addr_len, sizeof(uint32_t), 0) == 0) {
                    if (addr_len > 0 && addr_len <= 128) {
                        record->arg_data[4] = rr_capture_buffer(env, args[4], addr_len);
                        record->arg_size[4] = addr_len;
                        record->arg_data[5] = rr_capture_buffer(env, args[5], sizeof(uint32_t));
                        record->arg_size[5] = sizeof(uint32_t);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_bind
        case TARGET_NR_bind:
            /* Capture sockaddr structure */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_SOCKADDR_SIZE) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
            }
            break;
#endif

#ifdef TARGET_NR_listen
        case TARGET_NR_listen:
            /* listen parameters are simple (fd, backlog), no extra data capture required */
            break;
#endif

#ifdef TARGET_NR_getsockname
        case TARGET_NR_getsockname:
            /* Capture local address (output parameter) */
            if (ret == 0 && args[1] != 0 && args[2] != 0) {
                uint32_t addr_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[2], (uint8_t*)&addr_len, sizeof(uint32_t), 0) == 0) {
                    if (addr_len > 0 && addr_len <= RR_MAX_SOCKADDR_SIZE) {
                        record->arg_data[1] = rr_capture_buffer(env, args[1], addr_len);
                        record->arg_size[1] = addr_len;
                        record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(uint32_t));
                        record->arg_size[2] = sizeof(uint32_t);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_getpeername
        case TARGET_NR_getpeername:
            /* Capture peer address (output parameter) */
            if (ret == 0 && args[1] != 0 && args[2] != 0) {
                uint32_t addr_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[2], (uint8_t*)&addr_len, sizeof(uint32_t), 0) == 0) {
                    if (addr_len > 0 && addr_len <= RR_MAX_SOCKADDR_SIZE) {
                        record->arg_data[1] = rr_capture_buffer(env, args[1], addr_len);
                        record->arg_size[1] = addr_len;
                        record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(uint32_t));
                        record->arg_size[2] = sizeof(uint32_t);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_setsockopt
        case TARGET_NR_setsockopt:
            /* Capture socket option data (input parameter) */
            if (args[3] != 0 && args[4] > 0 && args[4] <= RR_MAX_IOCTL_PAYLOAD) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], args[4]);
                record->arg_size[3] = args[4];
            }
            break;
#endif

#ifdef TARGET_NR_getsockopt
        case TARGET_NR_getsockopt:
            /* Capture socket option data (output parameter) */
            if (ret == 0 && args[3] != 0 && args[4] != 0) {
                uint32_t opt_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[4], (uint8_t*)&opt_len, sizeof(uint32_t), 0) == 0) {
                    if (opt_len > 0 && opt_len <= RR_MAX_IOCTL_PAYLOAD) {
                        record->arg_data[3] = rr_capture_buffer(env, args[3], opt_len);
                        record->arg_size[3] = opt_len;
                        record->arg_data[4] = rr_capture_buffer(env, args[4], sizeof(uint32_t));
                        record->arg_size[4] = sizeof(uint32_t);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_recvmsg
        case TARGET_NR_recvmsg:
            /* recvmsg uses msghdr structure, containing iovec, control messages, etc. */
            if (ret > 0 && args[1] != 0) {
                /* Capture entire msghdr structure (simplified) */
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct msghdr));
                record->arg_size[1] = sizeof(struct msghdr);
                
                /* 🔥 Add aux_data for fuzzing */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
                /* TODO: Full implementation requires recursive capture of iovec and control messages */
            }
            break;
#endif

#ifdef TARGET_NR_sendmsg
        case TARGET_NR_sendmsg:
            /* sendmsg also uses msghdr structure */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct msghdr));
                record->arg_size[1] = sizeof(struct msghdr);
                
                /* 🔥 Add aux_data for fuzzing */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
                /* TODO: Full implementation requires recursive capture of iovec */
            }
            break;
#endif

        // Pipe related
#ifdef TARGET_NR_pipe
        case TARGET_NR_pipe:
            /* Capture the two returned file descriptors */
            if (ret == 0 && args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], 2 * sizeof(int));
                record->arg_size[0] = 2 * sizeof(int);
            }
            break;
#endif

#ifdef TARGET_NR_pipe2
        case TARGET_NR_pipe2:
            /* Similar to pipe but with additional flags parameter */
            if (ret == 0 && args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], 2 * sizeof(int));
                record->arg_size[0] = 2 * sizeof(int);
            }
            break;
#endif

        // Resource limits
        case TARGET_NR_prlimit64:
            /* Capture rlimit structure */
            if (args[2] != 0) {
                // New resource limit
                record->arg_data[2] = rr_capture_buffer(env, args[2], 16); // sizeof(struct rlimit64)
                record->arg_size[2] = 16;
            }
            if (ret == 0 && args[3] != 0) {
                // Old resource limit (return value)
                record->arg_data[3] = rr_capture_buffer(env, args[3], 16);
                record->arg_size[3] = 16;
            }
            break;

        // Phase 2: Expanded Syscall Support
        
#ifdef TARGET_NR_fcntl
        case TARGET_NR_fcntl:
#endif
#ifdef TARGET_NR_fcntl64
        case TARGET_NR_fcntl64:
#endif
#if defined(TARGET_NR_fcntl) || defined(TARGET_NR_fcntl64)
            /* fcntl's third argument depends on cmd */
            {
                int cmd = (int)args[1];
                switch (cmd) {
                    case F_GETFD:
                    case F_GETFL:
                    case F_GETOWN:
                        // These commands have no third argument
                        break;
                    case F_DUPFD:
                    case F_DUPFD_CLOEXEC:
                    case F_SETFD:
                    case F_SETFL:
                    case F_SETOWN:
                        // These commands have an integer third argument, already in args
                        break;
                    case F_GETLK:
                    case F_SETLK:
                    case F_SETLKW:
                        // These commands use struct flock
                        if (args[2] != 0) {
                            record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct flock));
                            record->arg_size[2] = sizeof(struct flock);
                        }
                        break;
                }
            }
            break;
#endif  // defined(TARGET_NR_fcntl) || defined(TARGET_NR_fcntl64)

#ifdef TARGET_NR_poll
        case TARGET_NR_poll:
            /* Capture pollfd array */
            if (args[0] != 0 && args[1] > 0 && args[1] <= RR_MAX_IOVEC_COUNT) {
                size_t pollfd_size = sizeof(struct pollfd) * args[1];
                record->arg_data[0] = rr_capture_buffer(env, args[0], pollfd_size);
                record->arg_size[0] = pollfd_size;
            }
            break;
#endif

#ifdef TARGET_NR_ppoll
        case TARGET_NR_ppoll:
            /* Similar to poll, but with timespec and sigmask */
            if (args[0] != 0 && args[1] > 0 && args[1] <= RR_MAX_IOVEC_COUNT) {
                size_t pollfd_size = sizeof(struct pollfd) * args[1];
                record->arg_data[0] = rr_capture_buffer(env, args[0], pollfd_size);
                record->arg_size[0] = pollfd_size;
            }
            if (args[2] != 0) {
                // timespec
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct timespec));
                record->arg_size[2] = sizeof(struct timespec);
            }
            break;
#endif

#ifdef TARGET_NR_epoll_wait
        case TARGET_NR_epoll_wait:
            /* Capture epoll_event array (output) */
            if (ret > 0 && args[1] != 0) {
                size_t events_size = sizeof(struct epoll_event) * ret;
                record->arg_data[1] = rr_capture_buffer(env, args[1], events_size);
                record->arg_size[1] = events_size;
            }
            break;
#endif

#ifdef TARGET_NR_epoll_pwait
        case TARGET_NR_epoll_pwait:
            /* Similar to epoll_wait but with sigmask */
            if (ret > 0 && args[1] != 0) {
                size_t events_size = sizeof(struct epoll_event) * ret;
                record->arg_data[1] = rr_capture_buffer(env, args[1], events_size);
                record->arg_size[1] = events_size;
            }
            break;
#endif

#ifdef TARGET_NR_select
        case TARGET_NR_select:
            /* Capture fd_set structure */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(fd_set));
                record->arg_size[1] = sizeof(fd_set);
            }
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(fd_set));
                record->arg_size[2] = sizeof(fd_set);
            }
            if (args[3] != 0) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(fd_set));
                record->arg_size[3] = sizeof(fd_set);
            }
            if (args[4] != 0) {
                record->arg_data[4] = rr_capture_buffer(env, args[4], sizeof(struct timeval));
                record->arg_size[4] = sizeof(struct timeval);
            }
            break;
#endif

#ifdef TARGET_NR_pselect6
        case TARGET_NR_pselect6:
            /* pselect6 is similar to select but uses timespec instead of timeval */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(fd_set));
                record->arg_size[1] = sizeof(fd_set);
            }
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(fd_set));
                record->arg_size[2] = sizeof(fd_set);
            }
            if (args[3] != 0) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(fd_set));
                record->arg_size[3] = sizeof(fd_set);
            }
            if (args[4] != 0) {
                record->arg_data[4] = rr_capture_buffer(env, args[4], sizeof(struct timespec));
                record->arg_size[4] = sizeof(struct timespec);
            }
            if (args[5] != 0) {
                /* sigmask */
                record->arg_data[5] = rr_capture_buffer(env, args[5], 8); // sizeof(sigset_t)
                record->arg_size[5] = 8;
            }
            break;
#endif

#ifdef TARGET_NR_nanosleep
        case TARGET_NR_nanosleep:
            /* Capture timespec structure (input and output) */
            if (args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], sizeof(struct timespec));
                record->arg_size[0] = sizeof(struct timespec);
            }
            if (ret == 0 && args[1] != 0) {
                /* Remaining time (optional, only if interrupted) */
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct timespec));
                record->arg_size[1] = sizeof(struct timespec);
            }
            break;
#endif

#ifdef TARGET_NR_clock_nanosleep
        case TARGET_NR_clock_nanosleep:
            /* clock_nanosleep is similar to nanosleep but with clock ID */
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct timespec));
                record->arg_size[2] = sizeof(struct timespec);
            }
            if (ret == 0 && args[3] != 0) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(struct timespec));
                record->arg_size[3] = sizeof(struct timespec);
            }
            break;
#endif

#ifdef TARGET_NR_timer_create
        case TARGET_NR_timer_create:
            /* timer_create returns timer_t (timer ID) */
            if (ret == 0 && args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(int)); // timer_t is int
                record->arg_size[2] = sizeof(int);
            }
            if (args[1] != 0) {
                /* sigevent structure */
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct sigevent));
                record->arg_size[1] = sizeof(struct sigevent);
            }
            break;
#endif

#ifdef TARGET_NR_timer_settime
        case TARGET_NR_timer_settime:
            /* Set timer */
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct itimerspec));
                record->arg_size[2] = sizeof(struct itimerspec);
            }
            if (ret == 0 && args[3] != 0) {
                /* Old value (optional) */
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(struct itimerspec));
                record->arg_size[3] = sizeof(struct itimerspec);
            }
            break;
#endif

#ifdef TARGET_NR_timerfd_create
        case TARGET_NR_timerfd_create:
            /* timerfd_create parameters are simple, returns fd */
            break;
#endif

#ifdef TARGET_NR_timerfd_settime
        case TARGET_NR_timerfd_settime:
            /* Set timerfd */
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct itimerspec));
                record->arg_size[2] = sizeof(struct itimerspec);
            }
            if (ret == 0 && args[3] != 0) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(struct itimerspec));
                record->arg_size[3] = sizeof(struct itimerspec);
            }
            break;
#endif

#ifdef TARGET_NR_signalfd
        case TARGET_NR_signalfd:
            /* Capture signal mask */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], 8); // sizeof(sigset_t)
                record->arg_size[1] = 8;
            }
            break;
#endif

#ifdef TARGET_NR_signalfd4
        case TARGET_NR_signalfd4:
            /* signalfd4 = signalfd + flags */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], 8); // sizeof(sigset_t)
                record->arg_size[1] = 8;
            }
            break;
#endif

        // More syscall special handling can be added here
        default:
            // For non-specially handled syscalls, do not capture parameter data
            break;
    }
}

/**
 * @brief Records a single syscall to the trace file.
 * 
 * Core function in Record mode, responsible for capturing full syscall info
 * and serializing it to the trace file. Called once by rr_syscall_post_hook()
 * after each guest syscall execution.
 * 
 * **Recorded Content**:
 * 1. Basic info: syscall number, arguments, return value, index.
 * 2. FD info: whether it creates/uses a file descriptor.
 * 3. Parameter data: for I/O syscalls, capture buffer contents.
 * 4. Aux data: EnvFuzz-style auxiliary data (recommended).
 * 
 * **Capture Strategy**:
 * - Uses the aux_data system by default (capture_syscall_args_aux).
 * - If use_legacy_capture=true, also uses the traditional method.
 * - ⚠️ Double capture issue: enabling both results in memory waste.
 * 
 * **File Format** (Binary):
 * ```
 * [index:uint32][syscall_nr:int32][args:8*abi_long][retval:abi_long]
 * [arg_sizes:8*size_t][creates_fd:bool][uses_fd:bool][created_fd:int32]
 * [arg_data_entries...][end_marker:-1]
 * [aux_data_magic:0x41555844][aux_data_entries...]
 * ```
 * 
 * @param env CPU architecture state pointer (for reading guest memory).
 * @param num Syscall number.
 * @param args Syscall argument array (8 arguments).
 * @param ret Syscall return value.
 * 
 * @return int
 *         - 0: Record successful.
 *         - -1: Record failed (trace file not open or write error).
 * 
 * @note Automatically updates g_rr_framework->trace_length.
 * @note Calls fflush() every 100 records to reduce I/O overhead.
 * @note Created syscall_record_t added to global list (trace_head/trace_tail).
 * 
 * @warning 🔥 Known issue: If use_legacy_capture=true, double capture occurs.
 *          - capture_syscall_args() calls rr_promote_arg_to_aux() to create aux_data.
 *          - capture_syscall_args_aux() captures the same data again.
 *          - Result: Duplicate entries in aux_data list, wasting memory and disk space.
 * @warning Do NOT add FD mappings during recording (handled by rr_syscall_post_hook).
 * 
 * @see rr_start_recording() Must be called first to open trace file.
 * @see rr_syscall_post_hook() Caller site.
 * @see capture_syscall_args() Traditional parameter capture.
 * @see capture_syscall_args_aux() Recommended aux_data capture.
 * @see syscall_creates_fd() Determine if syscall creates an FD.
 * @see g_trace_file Global trace file handle.
 */
int rr_record_syscall(CPUArchState *env, int num, const abi_long *args, abi_long ret)
{
    if (g_rr_config.mode != RR_MODE_RECORD || !g_trace_file) {
        return 0;
    }
    RR_VERBOSE("RECORD_SYSCALL: Called for syscall %d, ret=%ld", num, (long)ret);

    /* 🔥 Fix: Do not skip any syscalls to ensure record/replay consistency */
    /* Previously skipped mmap/brk/getpid caused replay mismatch */

    if (!g_trace_file) {
        RR_ERROR("Record syscall called but no trace file open");
        return -1;
    }

    RR_VERBOSE("RECORD_SYSCALL: Trace file is open, continuing with recording");
    RR_SYSCALL_TRACE("Recording syscall %d, ret=%ld", num, (long)ret);

    /* Create record */
    syscall_record_t *record = g_malloc0(sizeof(syscall_record_t));
    
    /* Use global written counter to guarantee 0,1,2... in file */
    record->index = g_written_count++;

    g_rr_framework->trace_length = g_written_count; // Sync back for consistency
    
    record->syscall_nr = num;

    for (int i = 0; i < 8; i++) {
        record->args[i] = (uint64_t)args[i];
    }
    record->retval = ret;



    RR_VERBOSE("RECORD_SYSCALL: Recording index=%u, syscall=%d, ret=%ld",
            record->index, record->syscall_nr, (long)record->retval);
    
    /* Update syscall index for BB trace */
    rr_bb_trace_update_syscall_idx(record->index);

    /* Detect FD creation */
    record->creates_fd = syscall_creates_fd(num, ret);
    if (record->creates_fd) {
        record->created_fd = (int32_t)ret;
        RR_FD_TRACE("Syscall %d creates FD: %d", num, record->created_fd);
        /* NOTE: FD mapping is handled in rr_syscall_post_hook; do not add during recording */
    }

    /* Smartly capture syscall parameter data */
    /* 
     * Resolve double-capture issues:
     * - Only use aux_data (EnvFuzz style) by default
     * - Only use legacy method if use_legacy_capture=true
     */
    if (g_rr_config.use_legacy_capture) {
        RR_VERBOSE("RECORD_SYSCALL: Using legacy capture for syscall %d", num);
        capture_syscall_args(env, num, args, ret, record);
    }
    
    /* Capture using aux_data system (recommended) */
    RR_VERBOSE("RECORD_SYSCALL: About to call capture_syscall_args_aux for syscall %d, ret=%ld, record=%p", 
               num, (long)ret, record);
    capture_syscall_args_aux(env, num, args, ret, record);
    RR_VERBOSE("RECORD_SYSCALL: After capture_syscall_args_aux, record=%p, has_aux_data=%d, aux_data=%p", 
               record, record->has_aux_data, record->aux_data);

    /* Add to trace linked list */
    if (g_rr_framework->trace_tail) {
        g_rr_framework->trace_tail->next = record;
    } else {
        g_rr_framework->trace_head = record;
    }
    g_rr_framework->trace_tail = record;

    /* Write to file - field by field to avoid alignment issues */
    RR_VERBOSE("RECORD_SYSCALL: Writing record to trace file (index=%u, syscall=%d)", record->index, num);
    
    // Write basic fields (using binary buffer)
    uint8_t buffer[8]; // 4 bytes for uint32_t + 4 bytes for int

    // Pack data manually into buffer
    uint32_t idx = record->index;
    int32_t sys = (int32_t)record->syscall_nr;

    /* Write index and syscall_nr (8 bytes total) */
    buffer[0] = (idx) & 0xFF;
    buffer[1] = (idx >> 8) & 0xFF;
    buffer[2] = (idx >> 16) & 0xFF;
    buffer[3] = (idx >> 24) & 0xFF;

    buffer[4] = (sys) & 0xFF;
    buffer[5] = (sys >> 8) & 0xFF;
    buffer[6] = (sys >> 16) & 0xFF;
    buffer[7] = (sys >> 24) & 0xFF;

    if (fwrite(buffer, 8, 1, g_trace_file) != 1) {
        RR_ERROR("Failed to write record header");
        return -1;
    }

    /* 🔥 Fix: standard fflush timing */
    if (g_rr_framework->trace_length % 100 == 0) {
        fflush(g_trace_file);
    }

    /* Fixed-width fields for universality - ALWAYS Little Endian */
    uint64_t fixed_args[8];
    for (int i = 0; i < 8; i++) fixed_args[i] = cpu_to_le64((uint64_t)record->args[i]);
    int64_t fixed_retval = (int64_t)cpu_to_le64((uint64_t)record->retval);
    uint64_t fixed_arg_sizes[8];
    for (int i = 0; i < 8; i++) fixed_arg_sizes[i] = cpu_to_le64((uint64_t)record->arg_size[i]);

    int32_t le_created_fd = (int32_t)cpu_to_le32((uint32_t)record->created_fd);

    if (fwrite(fixed_args, 8, 8, g_trace_file) != 8 ||
        fwrite(&fixed_retval, 8, 1, g_trace_file) != 1 ||
        fwrite(fixed_arg_sizes, 8, 8, g_trace_file) != 8 ||
        fwrite(&record->creates_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fwrite(&record->uses_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fwrite(&le_created_fd, sizeof(int32_t), 1, g_trace_file) != 1) {

        RR_ERROR("RECORD_SYSCALL: Failed to write syscall record fields");
        return -1;
    }

    /* Write parameter data */
    int arg_count = 0;
    for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
        if (record->arg_data[i] && record->arg_size[i] > 0) {
            RR_VERBOSE("RECORD_SYSCALL: Writing arg %d data (size=%lu)", i, (unsigned long)record->arg_size[i]);
            int32_t le_arg_idx = (int32_t)cpu_to_le32((uint32_t)i);
            uint64_t le_arg_size = cpu_to_le64(record->arg_size[i]);
            fwrite(&le_arg_idx, sizeof(int32_t), 1, g_trace_file);
            fwrite(&le_arg_size, sizeof(uint64_t), 1, g_trace_file);

            fwrite(record->arg_data[i], record->arg_size[i], 1, g_trace_file);
            arg_count++;
        }
    }

    /* Write end marker */
    int32_t end_marker = (int32_t)cpu_to_le32(0xFFFFFFFF); // -1 in LE
    fwrite(&end_marker, sizeof(int32_t), 1, g_trace_file);


    /* Write aux_data (if any) */
    RR_VERBOSE("RECORD_SYSCALL: Before aux write - record=%p, has_aux_data=%d, aux_data=%p", 
               record, record->has_aux_data, record->aux_data);
    if (record->has_aux_data && record->aux_data) {
        /* Write aux_data marker */
        uint32_t aux_magic = cpu_to_le32(0x41555844); // "AUXD"
        long pos_before = ftell(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: Writing AUXD magic 0x%08x at pos %ld", 0x41555844, pos_before);
        size_t written = fwrite(&aux_magic, sizeof(uint32_t), 1, g_trace_file);

        if (written != 1) {
            RR_ERROR("RECORD_SYSCALL: Failed to write AUXD magic!");
        }
        long pos_after = ftell(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: After writing AUXD, pos=%ld (delta=%ld)", pos_after, pos_after - pos_before);
        
        /* Count aux_data entries */
        uint32_t aux_count = 0;
        rr_aux_data_t *curr = record->aux_data;
        while (curr) {
            aux_count++;
            curr = curr->next;
        }
        uint32_t le_aux_count = cpu_to_le32(aux_count);
        fwrite(&le_aux_count, sizeof(uint32_t), 1, g_trace_file);

        
        /* Write each aux_data entry */
        curr = record->aux_data;
        while (curr) {
            uint32_t le_size = cpu_to_le32(curr->size);
            fwrite(&curr->kind, sizeof(uint8_t), 1, g_trace_file);
            fwrite(&curr->arg_mask, sizeof(uint8_t), 1, g_trace_file);
            fwrite(&le_size, sizeof(uint32_t), 1, g_trace_file);

            fwrite(curr->data, curr->size, 1, g_trace_file);
            
            RR_VERBOSE("RECORD_SYSCALL: Wrote aux_data kind=%d, arg=%d, size=%u",
                       curr->kind, curr->arg_mask, curr->size);
            curr = curr->next;
        }
    } else {
        /* Write no aux_data marker */
        uint32_t no_aux = 0;
        RR_VERBOSE("RECORD_SYSCALL: Writing no_aux marker (has_aux_data=%d, aux_data=%p)", 
                   record->has_aux_data, record->aux_data);
        fwrite(&no_aux, sizeof(uint32_t), 1, g_trace_file);
    }

    /* Always flush after writing record to ensure data integrity */
    fflush(g_trace_file);
    
#ifdef TARGET_NR_sendto
    if (num == TARGET_NR_sendto) {
        RR_INFO("RECORDED SENDTO: index=%u, has_aux=%d", record->index, record->has_aux_data);
    }
#endif
    RR_VERBOSE("RECORD_SYSCALL: Successfully recorded syscall %d (index=%u, args=%d, aux=%s, total_syscalls=%u)",
               num, record->index, arg_count, record->has_aux_data ? "yes" : "no", g_rr_framework->trace_length);
    const char *name = rr_get_syscall_name_fast(num);
    RR_LOG("Recorded syscall %d: %s -> %ld", record->index,
           name ? name : "unknown", (long)ret);

    /* Optimization: Update header every 100 records to reduce fseek overhead */
    if (g_rr_framework->trace_length % 100 == 0) {
        long header_pos = ftell(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: Before header update - ftell=%ld", header_pos);
        fseek(g_trace_file, sizeof(uint32_t) * 2, SEEK_SET);  // Skip magic and version
        uint32_t record_count = g_rr_framework->trace_length;
        fwrite(&record_count, sizeof(record_count), 1, g_trace_file);
        fseek(g_trace_file, header_pos, SEEK_SET);  // Restore position
        long after_seek = ftell(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: After header update - ftell=%ld (should be %ld)", after_seek, header_pos);
        fflush(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: Updated header with record_count=%u", record_count);
    }

    return 0;
}