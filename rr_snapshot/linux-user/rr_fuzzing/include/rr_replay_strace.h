/**
 * RR-Fuzz Strace Replay Module Header
 * Intelligent replay interface based on strace-formatted trace files.
 */

#ifndef RR_REPLAY_STRACE_H
#define RR_REPLAY_STRACE_H

#include <stdint.h>
#include <stdbool.h>

/* Forward declarations for QEMU types */
#include "qemu/osdep.h"
#include "user/abitypes.h"
#include "cpu.h"

/* Core API */

/**
 * Initialize strace replay module.
 * @param trace_file Path to strace-formatted trace file.
 * @return 0 on success, -1 on failure.
 */
int rr_strace_replay_init(const char *trace_file);

/**
 * Cleanup strace replay module.
 */
void rr_strace_replay_cleanup(void);

/**
 * Print detailed replay statistics.
 */
void rr_strace_replay_print_stats(void);


/**
 * Save statistics to a file.
 */
void rr_strace_save_stats_to_file(const char *filename);

/**
 * Set replay mode.
 */
void rr_strace_set_pure_replay_mode(bool enabled);

/**
 * Main syscall handling for strace replay.
 * Can be used as a replacement for rr_replay_syscall.
 * @param env CPU architecture state.
 * @param num Syscall number.
 * @param args Syscall arguments array.
 * @return Syscall return value, or -1 to let the system execute the original call.
 */
abi_long rr_replay_syscall_strace(CPUArchState *env, int num, abi_long *args);

/**
 * Check if strace replay is enabled.
 * @return true if enabled, false otherwise.
 */
bool rr_strace_replay_enabled(void);

/**
 * Hook after syscall execution (used for handle mapping).
 * @param env CPU architecture state.
 * @param num Syscall number.
 * @param ret Syscall return value.
 * @param args Syscall arguments array.
 */
void rr_strace_syscall_post_hook(CPUArchState *env, int num, abi_long ret, abi_long *args);

/**
 * Optimized hook after syscall execution (used for FD mapping and return value handling).
 * @param env CPU architecture state.
 * @param num Syscall number.
 * @param ret Syscall return value.
 * @param args Syscall arguments array.
 */
void rr_strace_syscall_post_hook_optimized(CPUArchState *env, int num, abi_long ret, abi_long *args);

/* Configuration Interface */

/**
 * Set strace replay mode.
 * @param strict_mode Whether to enable strict mode (exact parameter matching).
 * @param skip_unmatched Whether to skip unmatched syscalls.
 * @param max_lookahead Maximum lookahead matches.
 */
void rr_strace_set_mode(bool strict_mode, bool skip_unmatched, int max_lookahead);

/* Statistics and Debugging Interface */

/**
 * Get strace replay statistics.
 * @param total Total syscall count (optional, NULL to ignore).
 * @param matched Matched syscall count (optional, NULL to ignore).
 * @param skipped Skipped syscall count (optional, NULL to ignore).
 * @param errors Error syscall count (optional, NULL to ignore).
 */
void rr_strace_get_replay_stats(uint64_t *total, uint64_t *matched, 
                               uint64_t *skipped, uint64_t *errors);

/**
 * Print current strace replay status (for debugging).
 */
void rr_strace_print_status(void);

/* Constant Definitions */

/* strace replay mode constants */
#define RR_STRACE_MODE_STRICT       1   /* Strict mode */
#define RR_STRACE_MODE_LOOSE        0   /* Loose mode */
#define RR_STRACE_SKIP_UNMATCHED    1   /* Skip unmatched */
#define RR_STRACE_NO_SKIP           0   /* No skip */
#define RR_STRACE_DEFAULT_LOOKAHEAD 5   /* Default lookahead count */

#endif /* RR_REPLAY_STRACE_H */
