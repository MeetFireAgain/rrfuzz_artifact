/**
 * RR-Fuzz Pure Deterministic Replay Module
 * Pure Deterministic Replay - EnvFuzz style
 * 
 * Fully independent replay implementation:
 * - Complete restoration using AUX data
 * - No real syscall execution
 * - No argument modification (no FD mapping application)
 * - Fully deterministic execution
 */

#define RR_DEBUG 1

#include "rr_framework.h"
#include "rr_replay_pure.h"
#include "rr_aux_data.h"
#include <sys/mman.h>
#include <unistd.h>

/**
 * @brief Pure Deterministic Replay - Restore syscall in userspace without real execution
 * 
 * One of the core innovations of RR-Fuzz, implementing EnvFuzz-style deterministic replay.
 * For syscalls with captured aux_data, the memory state and return value are restored
 * directly from aux_data, COMPLETELY BYPASSING the real system call execution.
 * 
 * Benefits:
 * 1. Eliminates syscall overhead, improving replay performance.
 * 2. Avoids interaction with the OS, increasing determinism.
 * 3. Supports offline analysis (no actual file/network resources needed).
 * 
 * Supported Syscall Types:
 * - Input I/O: read, pread64, recv, recvfrom
 * - Non-deterministic sources: getrandom (Crucial! Ensures reproducibility of randomness)
 * - Special ioctl: ioctl commands with output buffers
 * - (Unsupported) Output I/O: write, send (Must execute to maintain I/O state)
 * - (Unsupported) Memory management: mmap, brk (Must execute to maintain QEMU memory mapping)
 * 
 * Principles:
 * 1. Check if record has aux_data (has_aux_data).
 * 2. Find corresponding aux_data entry based on syscall type (by arg_index).
 * 3. Write aux_data to guest memory using cpu_memory_rw_debug().
 * 4. Return recorded retval directly; QEMU will not execute the real syscall.
 * 
 * @param env CPU architecture state pointer (for guest memory writes)
 * @param num System call number
 * @param args System call arguments array (8 arguments), Pure replay might modify some
 * @param record Syscall record read from trace file (containing aux_data)
 * 
 * @return abi_long
 *         - >= 0: Pure replay successful, returns recorded retval
 *         - -1: Pure replay not supported or failed, fallback to Hybrid replay
 * 
 * @note Returns -1 immediately if no aux_data is present or if it's empty.
 * @note Force returns -1 for output calls like write/send to ensure real execution.
 * @note Force returns -1 for mmap/brk as QEMU must maintain memory mappings.
 * 
 * @warning cpu_memory_rw_debug failure logs an error and returns -1 (fallback to hybrid).
 * @warning Ensure aux_data arg_index matches the actual argument index.
 * 
 * @see rr_replay_syscall() Calls this function, if it returns -1, hybrid replay is executed.
 * @see rr_aux_find() Finds the entry with the specified arg_index from the aux_data linked list.
 * @see capture_syscall_args_aux() Corresponding function for creating aux_data during the Record phase.
 * @see cpu_memory_rw_debug() QEMU function for reading/writing guest memory.
 */
abi_long rr_replay_syscall_pure(CPUArchState *env, int num, abi_long *args,
                                syscall_record_t *record)
{
    if (!record->has_aux_data || !record->aux_data) {
        RR_VERBOSE("PURE_REPLAY: No aux_data for syscall %d", num);
        return -1; /* Fallback to hybrid */
    }

    RR_VERBOSE("PURE_REPLAY: Replaying syscall %d with aux_data", num);

    /* Restore from AUX data based on syscall type */
    switch (num) {
#ifdef TARGET_NR_brk
        case TARGET_NR_brk:
#endif
#if defined(TARGET_NR_mmap)
        case TARGET_NR_mmap:
#endif
#if defined(TARGET_NR_mmap2)
        case TARGET_NR_mmap2:
#endif
#if defined(TARGET_NR_brk) || defined(TARGET_NR_mmap) || defined(TARGET_NR_mmap2)
        {
            /* brk/mmap require real execution to maintain QEMU internal state; fallback directly */
            RR_VERBOSE("PURE_REPLAY: Syscall %d requires hybrid path, fallback", num);
            return -1;
        }
#endif

#ifdef TARGET_NR_read
        case TARGET_NR_read: {
            /* Restore read data from aux_data */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1); /* arg[1] is the buffer */
            if (aux && aux->data && aux->size > 0) {
                /* Write data to guest memory */
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes for read()", aux->size);
                    return record->retval; /* Return recorded retval, skip real read */
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write data for read()");
                }
            }
            break;
        }
#endif

#ifdef TARGET_NR_write
        case TARGET_NR_write:
#endif
#ifdef TARGET_NR_writev
        case TARGET_NR_writev:
#endif
#ifdef TARGET_NR_send
        case TARGET_NR_send:
#endif
#ifdef TARGET_NR_sendto
        case TARGET_NR_sendto:
#endif
#ifdef TARGET_NR_sendmsg
        case TARGET_NR_sendmsg:
#endif
#if defined(TARGET_NR_write) || defined(TARGET_NR_writev) || defined(TARGET_NR_send) || defined(TARGET_NR_sendto) || defined(TARGET_NR_sendmsg)
        {
            /* Pure replay: return recorded retval, skip real syscall.
             * Real execution would EBADF (accept() was pure-replayed → no real kernel fd),
             * polluting coverage with error-handling paths absent from production traffic. */
            RR_VERBOSE("PURE_REPLAY: write/send syscall %d returning recorded retval=%ld", num, record->retval);
            return record->retval;
        }
#endif

#ifdef TARGET_NR_getrandom
        case TARGET_NR_getrandom:
#else
        case 318: /* x86_64 getrandom */
#endif
        {
            /* Restore random data - Crucial for determinism */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 0); /* arg[0] is the buffer */
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[0], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes of random data", aux->size);
                    return record->retval;
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write random data");
                }
            }
            break;
        }

#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64: {
            /* Restore pread64 data */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes for pread64()", aux->size);
                    return record->retval;
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write data for pread64()");
                }
            }
            break;
        }
#endif

#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom: {
            /* Restore received network data */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes for recvfrom()", aux->size);
                    return record->retval;
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write data for recvfrom()");
                }
            }
            break;
        }
#endif

#ifdef TARGET_NR_recv
        case TARGET_NR_recv: {
            /* Restore recv data */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes for recv()", aux->size);
                    return record->retval;
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write data for recv()");
                }
            }
            break;
        }
#endif

/* send/sendto/sendmsg handled in write/send block above */

#ifdef TARGET_NR_ioctl
        case TARGET_NR_ioctl: {
            /* ioctl Pure Replay - Restore output buffer from AUX data */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 2); /* arg[2] is the buffer */
            if (aux && aux->kind == AUX_IOCTL_OUTPUT && aux->data && aux->size > 0) {
                /* Write back to output buffer directly */
                if (cpu_memory_rw_debug(env_cpu(env), args[2], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes ioctl output for cmd=0x%lx", 
                               aux->size, (unsigned long)args[1]);
                    return record->retval; /* Pure replay successful, return recorded retval */
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write ioctl output buffer");
                }
            } else {
                /* No captured output data, might be an unsupported ioctl command */
                RR_VERBOSE("PURE_REPLAY: No IOCTL_OUTPUT aux_data for ioctl cmd=0x%lx", (unsigned long)args[1]);
            }
            break;
        }
#endif



        /* Network Syscalls Support - Pure Replay */
        case TARGET_NR_bind:
        case TARGET_NR_listen:
        case TARGET_NR_setsockopt:
            /* These typically check inputs or set state but don't return data in buffers (mostly).
             * We just return the recorded retval to simulate success.
             */
            RR_VERBOSE("PURE_REPLAY: Network setup syscall %d, mocking success with ret=%ld", num, (long)record->retval);
            return record->retval;

#ifdef TARGET_NR_gettimeofday
        case TARGET_NR_gettimeofday: {
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 0);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[0], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored timeval for gettimeofday()");
                    return record->retval;
                }
            }
            break;
        }
#endif

#ifdef TARGET_NR_clock_gettime
        case TARGET_NR_clock_gettime: {
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored timespec for clock_gettime()");
                    return record->retval;
                }
            }
            break;
        }
#endif

        #ifdef TARGET_NR_accept
        case TARGET_NR_accept:
#endif
        case TARGET_NR_accept4:
        case TARGET_NR_getsockname:
        case TARGET_NR_getpeername: {
             /* These return a sockaddr in the second argument (args[1]) */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                 if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                     RR_VERBOSE("PURE_REPLAY: Restored %u bytes sockaddr for syscall %d", aux->size, num);
                 } else {
                     RR_ERROR("PURE_REPLAY: Failed to write sockaddr for syscall %d", num);
                 }
            }
            return record->retval;
        }
#ifdef TARGET_NR_socketcall
        case TARGET_NR_socketcall:
            RR_VERBOSE("PURE_REPLAY: socketcall (call=%ld), mocking success with ret=%ld", (long)args[0], (long)record->retval);
            return record->retval;
#endif

        default:
            /* Other syscalls not yet supported in Pure Replay */
            RR_VERBOSE("PURE_REPLAY: Syscall %d not supported in pure mode", num);
            return -1;
    }

    /* Fallback to hybrid mode if restoration didn't succeed */
    RR_VERBOSE("PURE_REPLAY: Failed to replay syscall %d, fallback to hybrid", num);
    return -1;
}

/**
 * Check if the syscall supports Pure Replay
 */
bool rr_replay_pure_supported(int syscall_nr)
{
    // RR_VERBOSE("PURE_REPLAY_SUPPORT: checking syscall %d\n", syscall_nr);
    switch (syscall_nr) {
        case TARGET_NR_brk:
            return true;
        case TARGET_NR_read:
        case TARGET_NR_write:
#ifdef TARGET_NR_getrandom
        case TARGET_NR_getrandom:
#else
        case 318: /* x86_64 getrandom */
#endif
#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64:
#endif
#ifdef TARGET_NR_pwrite64
        case TARGET_NR_pwrite64:
#endif
#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
#endif
#ifdef TARGET_NR_recv
        case TARGET_NR_recv:
#endif
#ifdef TARGET_NR_send
        case TARGET_NR_send:
        case TARGET_NR_sendto:
#endif
        case TARGET_NR_ioctl: /* Task2: ioctl Pure Replay */
        /* Network Syscalls */
        case TARGET_NR_bind:
        case TARGET_NR_listen:
        case TARGET_NR_setsockopt:
        #ifdef TARGET_NR_accept
        case TARGET_NR_accept:
#endif
        case TARGET_NR_accept4:
        case TARGET_NR_getsockname:
        case TARGET_NR_getpeername:
#ifdef TARGET_NR_gettimeofday
        case TARGET_NR_gettimeofday:
#endif
#ifdef TARGET_NR_clock_gettime
        case TARGET_NR_clock_gettime:
#endif
#ifdef TARGET_NR_socketcall
        case TARGET_NR_socketcall:
#endif
            return true;
        default:
            return false;
    }
}

/**
 * Print Pure Replay statistics
 */
void rr_replay_pure_print_stats(void)
{
    /* TODO: Add statistics */
    RR_INFO("Pure replay statistics: (not implemented yet)");
}

