/**
 * RR-Fuzz Pure Deterministic Replay Module Header
 * Pure Deterministic Replay - EnvFuzz style.
 */

#ifndef RR_REPLAY_PURE_H
#define RR_REPLAY_PURE_H

#include "qemu/osdep.h"
#include "user/abitypes.h"
#include "cpu.h"
#include "rr_framework.h"

/**
 * Replay a single syscall deterministically.
 * 
 * @param env CPU environment.
 * @param num Syscall number.
 * @param args Syscall arguments (unmodified raw arguments).
 * @param record trace record.
 * @return syscall return value on success, -1 on failure (requires fallback to hybrid).
 */
abi_long rr_replay_syscall_pure(CPUArchState *env, int num, abi_long *args,
                                syscall_record_t *record);

/**
 * Check if a syscall supports pure replay.
 * 
 * @param syscall_nr Syscall number.
 * @return true if supported, false otherwise.
 */
bool rr_replay_pure_supported(int syscall_nr);

/**
 * Print pure replay statistics.
 */
void rr_replay_pure_print_stats(void);

/* Phase 1: Pure Replay + Fuzzing Integration */

/**
 * Re-apply Pure Replay after aux_data mutation.
 * 
 * Called after aux_data has been mutated by Fuzzing to restore the
 * mutated data back into guest memory.
 * 
 * @param env CPU environment.
 * @param num Syscall number.
 * @param args Syscall arguments.
 * @param record trace record (containing mutated aux_data).
 * @return syscall return value on success, -1 on failure.
 */
abi_long rr_replay_syscall_pure_reapply(CPUArchState *env, int num, 
                                        abi_long *args,
                                        syscall_record_t *record);

#endif /* RR_REPLAY_PURE_H */

