/**
 * RR-Fuzz Syscall Classification Information
 * 
 * Based on the P_IO classification strategy from EnvFuzz.
 * Primarily focuses on fuzzing data-transfer syscalls.
 */

#ifndef RR_SYSCALL_INFO_H
#define RR_SYSCALL_INFO_H

#include <stdint.h>
#include <stdbool.h>

/* Syscall classes (referencing EnvFuzz) */
typedef enum {
    SYSCALL_CLASS_MISC = 0,    /* Miscellaneous */
    SYSCALL_CLASS_FD   = 1,    /* File descriptor management (open, close, socket...) */
    SYSCALL_CLASS_IO   = 2,    /* I/O data transfer - Fuzzing target! */
    SYSCALL_CLASS_INFO = 3,    /* Information query (stat, getpid...) */
    SYSCALL_CLASS_MEM  = 4,    /* Memory management (mmap, brk...) */
    SYSCALL_CLASS_SIG  = 5,    /* Signal handling */
    SYSCALL_CLASS_THR  = 6,    /* Thread management */
    SYSCALL_CLASS_PROC = 7,    /* Process management (fork, execve...) */
} syscall_class_t;

/* Syscall information */
typedef struct {
    int nr;                    /* Syscall number */
    const char *name;          /* Name */
    syscall_class_t class;     /* Classification */
    bool is_input;             /* Is input direction (read: true, write: false) */
} syscall_info_t;

/* ===== Core Functions ===== */

/**
 * Get syscall information.
 * @param syscall_nr Syscall number
 * @return Syscall info, or default if not found.
 */
const syscall_info_t *rr_get_syscall_info(int syscall_nr);

/**
 * Determine whether to auto fork (EnvFuzz strategy).
 * 
 * Necessary and sufficient conditions:
 * 1. P_IO class (data transfer)
 * 2. Inbound direction (input, e.g., read)
 * 3. Return value > 0 (data available)
 * 
 * @param syscall_nr Syscall number
 * @param ret Syscall return value
 * @return true if fork should occur
 */
bool rr_should_auto_fork(int syscall_nr, abi_long ret);

/**
 * Get syscall class name (for logging).
 */
const char *rr_get_syscall_class_name(syscall_class_t class);

#endif /* RR_SYSCALL_INFO_H */

