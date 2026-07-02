/**
 * Syscall Dispatch Optimization Implementation
 * Uses function pointer tables and hash tables to optimize syscall processing performance.
 */

#include "rr_syscall_dispatch.h"
#include "rr_constants.h"
#include "rr_mapping_manager.h"
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

/* ==================== Concrete Handler Implementations ==================== */

/* ==================== Concrete Handler Implementations ==================== */

/**
 * @brief Argument application function for file I/O syscalls.
 * 
 * In Replay mode, applies argument values from the trace record to the current syscall arguments.
 * Handles:
 * - openat/open: flags, mode
 * - read/write: count
 * - pread64: count, offset
 * - ioctl: request
 * 
 * @param record Trace record
 * @param args Current syscall argument array (modified in-place).
 */
static void apply_file_io_args(rr_strace_record_t *record, abi_long *args) {
    if (!record || !record->syscall_name) return;
    
    if (strcmp(record->syscall_name, "openat") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // flags
        if (record->arg_count > 3) args[3] = record->args[3].value; // mode
    } else if (strcmp(record->syscall_name, "read") == 0 || 
               strcmp(record->syscall_name, "write") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // count
    } else if (strcmp(record->syscall_name, "pread64") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // count
        if (record->arg_count > 3) args[3] = record->args[3].value; // offset
    } else if (strcmp(record->syscall_name, "writev") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // iovcnt
    } else if (strcmp(record->syscall_name, "ioctl") == 0) {
        if (record->arg_count > 1) args[1] = record->args[1].value; // request
    } else if (strcmp(record->syscall_name, "getdents64") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // count
    } else if (strcmp(record->syscall_name, "newfstatat") == 0) {
        if (record->arg_count > 3) args[3] = record->args[3].value; // flags
    }
}

/**
 * @brief FD mapping application for file I/O syscalls.
 * 
 * Replaces `recorded_fd` in arguments with `actual_fd`.
 * Applicable to: read, write, close, fstat, ioctl, getdents64, etc.
 * 
 * @param syscall_name Syscall name
 * @param args Syscall argument array (args[0] is typically the fd; modified in-place).
 * 
 * @note For openat/newfstatat, args[0] is dirfd and also requires mapping (unless AT_FDCWD).
 */
static void apply_file_io_fd_mapping(const char *syscall_name, abi_long *args) {
    if (strcmp(syscall_name, "read") == 0 || 
        strcmp(syscall_name, "write") == 0 ||
        strcmp(syscall_name, "pread64") == 0 ||
        strcmp(syscall_name, "writev") == 0 ||
        strcmp(syscall_name, "close") == 0 ||
        strcmp(syscall_name, "fstat") == 0 ||
        strcmp(syscall_name, "ioctl") == 0 ||
        strcmp(syscall_name, "getdents64") == 0) {
        args[0] = rr_fd_mapping_get(args[0]);
    } else if (strcmp(syscall_name, "openat") == 0 ||
               strcmp(syscall_name, "newfstatat") == 0) {
        if (args[0] != -100) { // AT_FDCWD
            args[0] = rr_fd_mapping_get(args[0]);
        }
    }
}

/**
 * @brief Post Hook for file I/O syscalls.
 * 
 * Called after syscall execution to establish and maintain FD mappings.
 * 
 * - open/openat/dup: Establish recorded_fd -> actual_fd mapping on success.
 * - close: Remove mapping on success.
 * 
 * @param record Trace record (contains recorded_fd / ret_value).
 * @param ret Actual return value (actual_fd).
 * @param args Syscall arguments.
 */
static void file_io_post_hook(rr_strace_record_t *record, abi_long ret, abi_long *args) {
    if (!record) return;
    
    if ((strcmp(record->syscall_name, "open") == 0 || strcmp(record->syscall_name, "openat") == 0) && ret >= 0) {
        abi_long recorded_fd = record->ret_value;
        abi_long actual_fd = ret;
        // Establish mapping: recorded_fd → actual_fd
        rr_fd_mapping_add(recorded_fd, actual_fd);
        
        fprintf(stderr, "[FD-MAPPING] %s: recorded_fd=%ld -> actual_fd=%ld\n", 
                record->syscall_name, (long)recorded_fd, (long)actual_fd);
    }
    // Handle dup/dup2 as well
    else if (strcmp(record->syscall_name, "dup") == 0 && ret >= 0) {
        abi_long recorded_fd = record->ret_value;
        abi_long actual_fd = ret;
        rr_fd_mapping_add(recorded_fd, actual_fd);
        fprintf(stderr, "[FD-MAPPING] dup: recorded_fd=%ld -> actual_fd=%ld\n", 
                (long)recorded_fd, (long)actual_fd);
    }
    // Remove mapping on close
    else if (strcmp(record->syscall_name, "close") == 0 && ret == 0) {
        abi_long recorded_fd = record->args[0].value;
        rr_fd_mapping_remove((int)recorded_fd);
        fprintf(stderr, "[FD-MAPPING] close: removed mapping for fd=%ld\n", (long)recorded_fd);
    }
}

/**
 * @brief Argument application for memory management syscalls.
 * 
 * Handles mmap, munmap, mprotect, brk, etc.
 * Key function is applying address mapping: Converting recorded_addr from trace to actual_addr.
 * 
 * @param record Trace record.
 * @param args Syscall argument array (address parameter args[0] modified in-place).
 * 
 * @note mmap's args[0] is a suggested address (hint).
 * @note munmap/mprotect's args[0] must be an exact match.
 */
static void apply_memory_args(rr_strace_record_t *record, abi_long *args) {
    if (!record || !record->syscall_name) return;
    
    if (strcmp(record->syscall_name, "mmap") == 0) {
        // Apply address mapping
        if (record->arg_count > 0) {
            target_ulong recorded_addr = (target_ulong)record->args[0].value;
            target_ulong mapped_addr = rr_addr_mapping_get(recorded_addr);
            args[0] = (abi_long)mapped_addr;
            
            if (recorded_addr != 0 && mapped_addr != recorded_addr) {
                fprintf(stderr, "[ADDR-MAPPING] mmap: recorded_addr=0x%lx -> mapped_addr=0x%lx\n",
                        (unsigned long)recorded_addr, (unsigned long)mapped_addr);
            }
        }
        if (record->arg_count > 4) args[4] = record->args[4].value; // fd (mapped in apply_memory_fd_mapping)
    } else if (strcmp(record->syscall_name, "mprotect") == 0) {
        // mprotect also requires address mapping
        if (record->arg_count > 0) {
            target_ulong recorded_addr = (target_ulong)record->args[0].value;
            target_ulong mapped_addr = rr_addr_mapping_get(recorded_addr);
            
            // Critical Fix: If mapping not found, do not force use of trace address.
            // For unmappable addresses (like VDSO, dynamic linker regions), skip modification.
            if (recorded_addr != 0 && mapped_addr != recorded_addr) {
                args[0] = (abi_long)mapped_addr;
                fprintf(stderr, "[ADDR-MAPPING] mprotect: recorded_addr=0x%lx -> mapped_addr=0x%lx\n",
                        (unsigned long)recorded_addr, (unsigned long)mapped_addr);
            } else {
                // Mapping not found, keep current parameter (let syscall execute naturally)
                fprintf(stderr, "[ADDR-MAPPING-SKIP] mprotect: addr=0x%lx not in mapping table, using current value\n",
                        (unsigned long)recorded_addr);
            }
        }
        if (record->arg_count > 1) args[1] = record->args[1].value; // len
        if (record->arg_count > 2) args[2] = record->args[2].value; // prot
    } else if (strcmp(record->syscall_name, "munmap") == 0) {
        // munmap also requires address mapping
        if (record->arg_count > 0) {
            target_ulong recorded_addr = (target_ulong)record->args[0].value;
            target_ulong mapped_addr = rr_addr_mapping_get(recorded_addr);
            args[0] = (abi_long)mapped_addr;
        }
    }
}

/**
 * @brief FD mapping application for memory management syscalls.
 * 
 * Specifically handles the fd parameter (args[4]) for mmap.
 * If not an anonymous mapping (fd != -1), applies FD mapping.
 * 
 * @param syscall_name Syscall name.
 * @param args Syscall argument array.
 */
static void apply_memory_fd_mapping(const char *syscall_name, abi_long *args) {
    if (strcmp(syscall_name, "mmap") == 0) {
        // mmap's parameter 4 is FD (-1 for anonymous mapping)
        if (args[4] != (abi_long)-1) {
            abi_long recorded_fd = args[4];  // FD recorded in trace
            
            // Query mapping table: recorded_fd → actual_fd
            abi_long actual_fd = rr_fd_mapping_get(recorded_fd);
            
            if (actual_fd != -1) {
                args[4] = actual_fd;  // Use actual FD
                fprintf(stderr, "[FD-MAPPING] mmap: recorded_fd=%ld -> actual_fd=%ld\n", 
                        (long)recorded_fd, (long)actual_fd);
            } else {
                fprintf(stderr, "[FD-MAPPING-WARN] mmap: No mapping for recorded_fd=%ld, using as-is\n", 
                        (long)recorded_fd);
                // Keep original value and let syscall attempt execution
            }
        }
    }
}

/**
 * @brief Post Hook for memory management syscalls.
 * 
 * Core function: Maintain Address Mapping table.
 * Due to ASLR, mmap addresses during replay typically differ from those during recording.
 * 
 * - mmap success: Establish recorded_addr -> actual_addr mapping.
 * - munmap success: Remove mapping.
 * 
 * @param record Trace record (contains recorded_addr).
 * @param ret Actual return value (actual_addr).
 * @param args Arguments.
 */
static void memory_post_hook(rr_strace_record_t *record, abi_long ret, abi_long *args) {
    if (!record) return;
    
    if (strcmp(record->syscall_name, "mmap") == 0) {
        fprintf(stderr, "[MEMORY-POST-HOOK] mmap: ret=%ld, recorded_ret=%lu, MAP_FAILED=%ld\n",
                (long)ret, (unsigned long)record->ret_value, (long)MAP_FAILED);
        
        if (ret != (abi_long)-1 && record->ret_value != (target_ulong)-1) {
            target_ulong recorded_addr = (target_ulong)record->ret_value;
            target_ulong actual_addr = (target_ulong)ret;
            size_t size = (size_t)record->args[1].value;
            
            fprintf(stderr, "[ADDR-MAPPING-ADD] mmap: recorded=0x%lx -> actual=0x%lx, size=%zu\n",
                    (unsigned long)recorded_addr, (unsigned long)actual_addr, size);
            
            rr_addr_mapping_add(recorded_addr, actual_addr, size);
        } else {
            fprintf(stderr, "[MEMORY-POST-HOOK] mmap: SKIPPED address mapping (failed)\n");
        }
    } else if (strcmp(record->syscall_name, "munmap") == 0) {
        if (ret == 0 && record->ret_value == 0) {
            target_ulong recorded_addr = (target_ulong)record->args[0].value;
            fprintf(stderr, "[ADDR-MAPPING-REMOVE] munmap: recorded=0x%lx\n",
                    (unsigned long)recorded_addr);
            rr_addr_mapping_remove(recorded_addr);
        }
    }
}

/* Network-related syscall handling */

/**
 * @brief Argument application for network syscalls.
 * 
 * Handles socket, connect, bind, etc.
 * Complex network structures are partially handled:
 * - socket: Ensures protocol family/type/protocol consistency.
 * - bind/connect: Passes `addrlen`.
 * 
 * @param record Trace record.
 * @param args Syscall arguments.
 */
static void apply_network_args(rr_strace_record_t *record, abi_long *args) {
    if (!record || !record->syscall_name) return;
    
    if (strcmp(record->syscall_name, "socket") == 0) {
        // All arguments are numeric; use recorded values.
        for (int i = 0; i < record->arg_count && i < 3; i++) {
            args[i] = record->args[i].value;
        }
    } else if (strcmp(record->syscall_name, "bind") == 0 ||
               strcmp(record->syscall_name, "connect") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // addrlen
    }
}

/**
 * @brief Post Hook for network syscalls.
 * 
 * Core function: Maintain Socket FD mapping.
 * When socket/accept creates a new Socket FD, records recorded_fd -> actual_fd mapping.
 * 
 * @param record Trace record.
 * @param ret Actual return value (Socket FD).
 * @param args Arguments.
 */
static void network_post_hook(rr_strace_record_t *record, abi_long ret, abi_long *args) {
    if (!record) return;
    
    if (strcmp(record->syscall_name, "socket") == 0 ||
        strcmp(record->syscall_name, "accept") == 0 ||
        strcmp(record->syscall_name, "accept4") == 0) {
        if (ret >= 0 && record->ret_value >= 0) {
            rr_fd_mapping_add(record->ret_value, ret);
        }
    }
}

/* Generic handler functions */
static void apply_generic_args(rr_strace_record_t *record, abi_long *args) {
    if (!record) return;
    
    // Special case: Certain syscalls should not modify arguments.
    // These calls depend heavily on the current execution environment.
    if (record->syscall_name) {
        if (strcmp(record->syscall_name, "arch_prctl") == 0 ||
            strcmp(record->syscall_name, "brk") == 0 ||
            strcmp(record->syscall_name, "set_tid_address") == 0 ||
            strcmp(record->syscall_name, "set_robust_list") == 0) {
            // These syscall parameters should not be replayed.
            // They need to use actual addresses from the current process.
            return;
        }
    }
    
    // Generic strategy: Use recorded values for numeric arguments, maintain original values for pointers.
    for (int i = 0; i < record->arg_count && i < RR_MAX_SYSCALL_ARGS; i++) {
        if (record->args[i].type == RR_STRACE_ARG_TYPE_INT) {
            args[i] = record->args[i].value;
        }
    }
}

static void generic_post_hook(rr_strace_record_t *record, abi_long ret, abi_long *args) {
    // Default: No special processing
    (void)record;
    (void)ret;
    (void)args;
}

/* ==================== Syscall Handler Table Definition ==================== */

static rr_syscall_handler_t syscall_handlers[] = {
    /* File I/O Class */
#ifdef TARGET_NR_read
    {"read", TARGET_NR_read, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_CRITICAL, 
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_write
    {"write", TARGET_NR_write, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_open
    {"open", TARGET_NR_open, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_CRITICAL,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_close
    {"close", TARGET_NR_close, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_CRITICAL,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_ioctl
    {"ioctl", TARGET_NR_ioctl, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_pread64
    {"pread64", TARGET_NR_pread64, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_openat
    {"openat", TARGET_NR_openat, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_writev
    {"writev", TARGET_NR_writev, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_CRITICAL,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_getdents64
    {"getdents64", TARGET_NR_getdents64, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_newfstatat
    {"newfstatat", TARGET_NR_newfstatat, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_faccessat
    {"faccessat", TARGET_NR_faccessat, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_faccessat2
    {"faccessat2", TARGET_NR_faccessat2, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_renameat
    {"renameat", TARGET_NR_renameat, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_renameat2
    {"renameat2", TARGET_NR_renameat2, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_unlinkat
    {"unlinkat", TARGET_NR_unlinkat, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_mkdirat
    {"mkdirat", TARGET_NR_mkdirat, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_readlinkat
    {"readlinkat", TARGET_NR_readlinkat, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_symlinkat
    {"symlinkat", TARGET_NR_symlinkat, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_statx
    {"statx", TARGET_NR_statx, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
    
    /* Memory Management Class */
#ifdef TARGET_NR_mmap
    {"mmap", TARGET_NR_mmap, SYSCALL_TYPE_MEMORY, SYSCALL_IMPORTANCE_CRITICAL,
     apply_memory_args, apply_memory_fd_mapping, memory_post_hook, true, true, true},
#endif
#ifdef TARGET_NR_mmap2
    {"mmap2", TARGET_NR_mmap2, SYSCALL_TYPE_MEMORY, SYSCALL_IMPORTANCE_CRITICAL,
     apply_memory_args, apply_memory_fd_mapping, memory_post_hook, true, true, true},
#endif
#ifdef TARGET_NR_munmap
    {"munmap", TARGET_NR_munmap, SYSCALL_TYPE_MEMORY, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_memory_args, NULL, memory_post_hook, false, true, false},
#endif
#ifdef TARGET_NR_mprotect
    {"mprotect", TARGET_NR_mprotect, SYSCALL_TYPE_MEMORY, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_memory_args, NULL, memory_post_hook, false, true, false},
#endif
#ifdef TARGET_NR_brk
    {"brk", TARGET_NR_brk, SYSCALL_TYPE_MEMORY, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_memory_args, NULL, memory_post_hook, false, true, false},
#endif
    
    /* Network Class */
#ifdef TARGET_NR_socket
    {"socket", TARGET_NR_socket, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_bind
    {"bind", TARGET_NR_bind, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_listen
    {"listen", TARGET_NR_listen, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_connect
    {"connect", TARGET_NR_connect, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_accept
    {"accept", TARGET_NR_accept, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_accept4
    {"accept4", TARGET_NR_accept4, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_sendto
    {"sendto", TARGET_NR_sendto, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_CRITICAL,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_recvfrom
    {"recvfrom", TARGET_NR_recvfrom, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_CRITICAL,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_sendmsg
    {"sendmsg", TARGET_NR_sendmsg, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_recvmsg
    {"recvmsg", TARGET_NR_recvmsg, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_getsockname
    {"getsockname", TARGET_NR_getsockname, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_getpeername
    {"getpeername", TARGET_NR_getpeername, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_setsockopt
    {"setsockopt", TARGET_NR_setsockopt, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_getsockopt
    {"getsockopt", TARGET_NR_getsockopt, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_shutdown
    {"shutdown", TARGET_NR_shutdown, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_epoll_create
    {"epoll_create", TARGET_NR_epoll_create, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_epoll_create1
    {"epoll_create1", TARGET_NR_epoll_create1, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_epoll_ctl
    {"epoll_ctl", TARGET_NR_epoll_ctl, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_epoll_wait
    {"epoll_wait", TARGET_NR_epoll_wait, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_epoll_pwait
    {"epoll_pwait", TARGET_NR_epoll_pwait, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_socketcall
    {"socketcall", TARGET_NR_socketcall, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     NULL, NULL, NULL, false, false, false},
#endif
    
    /* System Information Class */
#ifdef TARGET_NR_getpid
    {"getpid", TARGET_NR_getpid, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_getuid
    {"getuid", TARGET_NR_getuid, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_getgid
    {"getgid", TARGET_NR_getgid, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_uname
    {"uname", TARGET_NR_uname, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_arch_prctl
    {"arch_prctl", TARGET_NR_arch_prctl, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_set_tid_address
    {"set_tid_address", TARGET_NR_set_tid_address, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_set_robust_list
    {"set_robust_list", TARGET_NR_set_robust_list, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_statfs
    {"statfs", TARGET_NR_statfs, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_prlimit64
    {"prlimit64", TARGET_NR_prlimit64, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_getrandom
    {"getrandom", TARGET_NR_getrandom, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_rseq
    {"rseq", TARGET_NR_rseq, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_access
    {"access", TARGET_NR_access, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_fstat
    {"fstat", TARGET_NR_fstat, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_fstat64
    {"fstat64", TARGET_NR_fstat64, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
    
    /* Process Management Class */
#ifdef TARGET_NR_clone
    {"clone", TARGET_NR_clone, SYSCALL_TYPE_PROCESS, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_fork
    {"fork", TARGET_NR_fork, SYSCALL_TYPE_PROCESS, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
#ifdef TARGET_NR_exit_group
    {"exit_group", TARGET_NR_exit_group, SYSCALL_TYPE_PROCESS, SYSCALL_IMPORTANCE_CRITICAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
#endif
    
#ifdef TARGET_NR_fcntl
    {"fcntl", TARGET_NR_fcntl, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_fcntl64
    {"fcntl64", TARGET_NR_fcntl64, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
#endif
#ifdef TARGET_NR_rt_sigprocmask
    {"rt_sigprocmask", TARGET_NR_rt_sigprocmask, SYSCALL_TYPE_SIGNAL, SYSCALL_IMPORTANCE_ENVIRONMENT,
     NULL, NULL, NULL, false, false, false},
#endif
#ifdef TARGET_NR_select
    {"select", TARGET_NR_select, SYSCALL_TYPE_TIME, SYSCALL_IMPORTANCE_IMPORTANT,
     NULL, NULL, NULL, false, false, false},
#endif
#ifdef TARGET_NR__newselect
    {"_newselect", TARGET_NR__newselect, SYSCALL_TYPE_TIME, SYSCALL_IMPORTANCE_IMPORTANT,
     NULL, NULL, NULL, false, false, false},
#endif
#ifdef TARGET_NR_wait4
    {"wait4", TARGET_NR_wait4, SYSCALL_TYPE_PROCESS, SYSCALL_IMPORTANCE_IMPORTANT,
     NULL, NULL, NULL, false, false, false},
#endif
    
    {NULL, -1, SYSCALL_TYPE_UNKNOWN, SYSCALL_IMPORTANCE_ENVIRONMENT, NULL, NULL, NULL, false, false, false}
};

/* ==================== Fast Lookup Table ==================== */

#define MAX_SYSCALL_NR 10000
static rr_syscall_handler_t* syscall_lookup_table[MAX_SYSCALL_NR];
static bool dispatch_initialized = false;

/* ==================== Public Interface Implementation ==================== */

/**
 * @brief Initialize Syscall Dispatch system.
 * 
 * Builds the fast syscall lookup table, converting linear scans to O(1) array index lookups.
 * This is a critical performance optimization.
 * 
 * @return int 0 on success.
 */
int rr_syscall_dispatch_init(void) {
    if (dispatch_initialized) {
        return 0;
    }
    
    // Initialize lookup table
    memset(syscall_lookup_table, 0, sizeof(syscall_lookup_table));
    
    // Populate lookup table
    for (int i = 0; syscall_handlers[i].name != NULL; i++) {
        int nr = syscall_handlers[i].syscall_nr;
        if (nr >= 0 && nr < MAX_SYSCALL_NR) {
            syscall_lookup_table[nr] = &syscall_handlers[i];
        }
    }
    
    dispatch_initialized = true;
    return 0;
}

void rr_syscall_dispatch_cleanup(void) {
    dispatch_initialized = false;
    memset(syscall_lookup_table, 0, sizeof(syscall_lookup_table));
}

/**
 * @brief Get syscall handler (O(1) lookup).
 * 
 * Quickly retrieves the handler set for a given `syscall_nr`.
 * 
 * @param syscall_nr Syscall number.
 * @return rr_syscall_handler_t* Handler pointer, or NULL if not registered.
 */
rr_syscall_handler_t* rr_get_syscall_handler(int syscall_nr) {
    if (!dispatch_initialized) {
        rr_syscall_dispatch_init();
    }
    
    if (syscall_nr >= 0 && syscall_nr < MAX_SYSCALL_NR) {
        return syscall_lookup_table[syscall_nr];
    }
    return NULL;
}

rr_syscall_handler_t* rr_get_syscall_handler_by_name(const char *name) {
    if (!name || !dispatch_initialized) {
        return NULL;
    }
    
    for (int i = 0; syscall_handlers[i].name != NULL; i++) {
        if (strcmp(syscall_handlers[i].name, name) == 0) {
            return &syscall_handlers[i];
        }
    }
    return NULL;
}

const char* rr_get_syscall_name_fast(int syscall_nr) {
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    return handler ? handler->name : NULL;
}

syscall_type_t rr_get_syscall_type(int syscall_nr) {
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    return handler ? handler->type : SYSCALL_TYPE_UNKNOWN;
}

syscall_importance_t rr_get_syscall_importance(int syscall_nr) {
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    return handler ? handler->importance : SYSCALL_IMPORTANCE_ENVIRONMENT;
}

/* ==================== Optimized Handler Functions ==================== */

/**
 * @brief Optimized parameter application entry point.
 * 
 * Replaces the original switch-case structure with handler table dispatch.
 * If a handler is found, its `apply_args` function is called; otherwise falls back to `apply_generic_args`.
 * 
 * @param record Trace record.
 * @param args Argument array.
 */
void rr_apply_syscall_args_optimized(rr_strace_record_t *record, abi_long *args) {
    if (!record || !args) return;
    
    rr_syscall_handler_t *handler = rr_get_syscall_handler_by_name(record->syscall_name);
    if (handler && handler->apply_args) {
        handler->apply_args(record, args);
    } else {
        // Fallback to generic handling
        apply_generic_args(record, args);
    }
}

void rr_apply_fd_mapping_optimized(int syscall_nr, abi_long *args) {
    if (!args) return;
    
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    if (handler && handler->needs_fd_mapping && handler->apply_fd_mapping) {
        handler->apply_fd_mapping(handler->name, args);
    }
}

/**
 * @brief Optimized Post Hook entry point.
 * 
 * Dispatches to specific post_hooks (e.g., `memory_post_hook` for address mapping) based on `syscall_nr`.
 * This design decouples logic from `rr_main.c`.
 * 
 * @param syscall_nr Syscall number.
 * @param record Trace record.
 * @param ret Return value.
 * @param args Arguments.
 */
void rr_syscall_post_hook_optimized(int syscall_nr, rr_strace_record_t *record, 
                                  abi_long ret, abi_long *args) {
    /* Removed redundant output for performance */
    
    if (!record || !args) {
        return;
    }
    
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    
    if (handler && handler->post_hook) {
        handler->post_hook(record, ret, args);
    }
}

