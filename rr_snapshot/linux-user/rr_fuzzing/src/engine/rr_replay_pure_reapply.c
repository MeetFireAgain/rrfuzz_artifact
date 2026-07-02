/**
 * RR-Fuzz Phase 1: Pure Replay Reapply
 * 
 * Re-applies mutated aux_data back to guest memory after Fuzzing mutation.
 * 
 * Design Concept:
 * 1. Pure Replay first restores original aux_data.
 * 2. Fuzzing mutates aux_data.
 * 3. Reapply restores mutated aux_data to guest memory.
 * 4. Program continues execution with the mutated data.
 */

#include "rr_framework.h"
#include "rr_replay_pure.h"
#include "rr_aux_data.h"

/**
 * Re-apply Pure Replay after aux_data mutation.
 * 
 * Core Logic:
 * - aux_data has been mutated by rr_fuzz_mutate_aux_data().
 * - Mutated aux_data must be written back to guest memory.
 * - Return value may need adjustment (e.g., if size changed).
 */
abi_long rr_replay_syscall_pure_reapply(CPUArchState *env, int num, 
                                        abi_long *args,
                                        syscall_record_t *record)
{
    if (!record || !record->has_aux_data || !record->aux_data) {
        RR_VERBOSE("PURE_REAPPLY: No aux_data to reapply");
        return -1;
    }
    
    RR_VERBOSE("PURE_REAPPLY: Reapplying mutated aux_data for syscall %d", num);
    
    /* Restore data based on syscall type */
    switch (num) {
        /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         * Input Syscalls: read, recv, getrandom, etc.
         * These require writing aux_data back to the specified buffer.
         * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
        
        case TARGET_NR_read: {
            /* read(fd, buf, count) - buf at arg[1] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1); /* arg[1]: stored as raw index */
            if (aux && aux->data && aux->size > 0) {
                /* Write mutated data to guest memory */
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: read() - reapplied %u bytes (mutated)", aux->size);
                    /* Return value may change (e.g., if size was truncated or extended) */
                    return (abi_long)aux->size;
                } else {
                    RR_ERROR("PURE_REAPPLY: read() - failed to write to guest memory");
                    return -1;
                }
            }
            break;
        }
        
#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64: {
            /* pread64(fd, buf, count, offset) - buf at arg[1] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: pread64() - reapplied %u bytes", aux->size);
                    return (abi_long)aux->size;
                }
            }
            break;
        }
#endif
        
        case TARGET_NR_getrandom: {
            /* getrandom(buf, buflen, flags) - buf at arg[0] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 0); /* arg[0]: stored as raw index */
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[0], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: getrandom() - reapplied %u bytes of mutated random data", 
                           aux->size);
                    return (abi_long)aux->size;
                }
            }
            break;
        }
        
#ifdef TARGET_NR_recv
        case TARGET_NR_recv: {
            /* recv(sockfd, buf, len, flags) - buf at arg[1] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: recv() - reapplied %u bytes of mutated network data", 
                           aux->size);
                    return (abi_long)aux->size;
                }
            }
            break;
        }
#endif
        
#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom: {
            /* recvfrom(sockfd, buf, len, flags, src_addr, addrlen) - buf at arg[1] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: recvfrom() - reapplied %u bytes", aux->size);
                    return (abi_long)aux->size;
                }
            }
            break;
        }
#endif
        
        /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         * Output Syscalls: write, send, etc.
         * 
         * Note: These syscalls are typically not supported in Pure Replay,
         * but can handle parameter mutations if support is extended.
         * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
        
        case TARGET_NR_write:
#ifdef TARGET_NR_pwrite64
        case TARGET_NR_pwrite64:
#endif
#ifdef TARGET_NR_send
        case TARGET_NR_send:
#endif
#ifdef TARGET_NR_sendto
        case TARGET_NR_sendto:
#endif
        {
            /* Output syscalls: Reapply usually not needed as data exists in guest memory.
             * However, can handle mutations to output buffers if necessary.
             */
            RR_VERBOSE("PURE_REAPPLY: Output syscall %d - no reapply needed", num);
            return record->retval;
        }
        
        /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         * Struct Syscalls (Phase 2 Extension)
         * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
        
        /* Phase 2 Implementations */
        // case TARGET_NR_stat:
        // case TARGET_NR_gettimeofday:
        // case TARGET_NR_clock_gettime:
        // etc.
        
        default:
            RR_VERBOSE("PURE_REAPPLY: Syscall %d not supported for reapply", num);
            return -1;
    }
    
    /* Fallthrough if reapply unsuccessful */
    RR_VERBOSE("PURE_REAPPLY: Failed to reapply for syscall %d", num);
    return -1;
}
