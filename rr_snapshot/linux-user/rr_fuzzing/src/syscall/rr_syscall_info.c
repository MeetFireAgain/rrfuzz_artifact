/**
 * RR-Fuzz Syscall Classification Information Implementation
 */

#include "rr_framework.h"
#include "rr_syscall_info.h"

/* Syscall number definitions */
#ifndef __NR_read
#include <sys/syscall.h>
#endif

/* ===== Syscall Classification Table ===== */
/**
 * @brief Syscall Classification Table (P0 Key Data Structure)
 * 
 * Defines classification information for all supported syscalls.
 * 
 * **Class**:
 * - `SYSCALL_CLASS_IO`:   I/O operations (Fuzzing target)
 * - `SYSCALL_CLASS_FD`:   File descriptor management (open, close, socket)
 * - `SYSCALL_CLASS_MEM`:  Memory management (mmap, brk)
 * - `SYSCALL_CLASS_PROC`: Process control (fork, exec)
 * 
 * **Attributes**:
 * - `is_input`: Marks whether the syscall is an input source (e.g., read is input, write is not).
 *               Crucial for the Auto Fork strategy.
 */
static const syscall_info_t g_syscall_table[] = {
    /* ===== SYSCALL_CLASS_IO (18) - Fuzzing Targets ===== */
    /* These syscalls transfer data and are the primary targets for fuzzing. */
    
    /* File I/O */
    {__NR_read,          "read",          SYSCALL_CLASS_IO, true},
    {__NR_write,         "write",         SYSCALL_CLASS_IO, false},
#ifdef __NR_pread64
    {__NR_pread64,       "pread64",       SYSCALL_CLASS_IO, true},
#endif
#ifdef __NR_pwrite64
    {__NR_pwrite64,      "pwrite64",      SYSCALL_CLASS_IO, false},
#endif
    {__NR_readv,         "readv",         SYSCALL_CLASS_IO, true},
    {__NR_writev,        "writev",        SYSCALL_CLASS_IO, false},
#ifdef __NR_preadv
    {__NR_preadv,        "preadv",        SYSCALL_CLASS_IO, true},
#endif
#ifdef __NR_pwritev
    {__NR_pwritev,       "pwritev",       SYSCALL_CLASS_IO, false},
#endif
    
    /* Network I/O */
    {__NR_sendto,        "sendto",        SYSCALL_CLASS_IO, false},
    {__NR_recvfrom,      "recvfrom",      SYSCALL_CLASS_IO, true},
    {__NR_sendmsg,       "sendmsg",       SYSCALL_CLASS_IO, false},
    {__NR_recvmsg,       "recvmsg",       SYSCALL_CLASS_IO, true},
#ifdef __NR_sendmmsg
    {__NR_sendmmsg,      "sendmmsg",      SYSCALL_CLASS_IO, false},
#endif
#ifdef __NR_recvmmsg
    {__NR_recvmmsg,      "recvmmsg",      SYSCALL_CLASS_IO, true},
#endif
    
    /* Device and Directory I/O */
    {__NR_ioctl,         "ioctl",         SYSCALL_CLASS_IO, true},
    {__NR_getdents,      "getdents",      SYSCALL_CLASS_IO, true},
#ifdef __NR_getdents64
    {__NR_getdents64,    "getdents64",    SYSCALL_CLASS_IO, true},
#endif
    
    /* ===== SYSCALL_CLASS_FD - File Descriptor Management ===== */
    /* These syscalls manage file descriptors and do not transfer data. */
    {__NR_open,          "open",          SYSCALL_CLASS_FD, false},
    {__NR_openat,        "openat",        SYSCALL_CLASS_FD, false},
    {__NR_close,         "close",         SYSCALL_CLASS_FD, false},
    {__NR_socket,        "socket",        SYSCALL_CLASS_FD, false},
    {__NR_accept,        "accept",        SYSCALL_CLASS_FD, false},
#ifdef __NR_accept4
    {__NR_accept4,       "accept4",       SYSCALL_CLASS_FD, false},
#endif
    {__NR_connect,       "connect",       SYSCALL_CLASS_FD, false},
    {__NR_bind,          "bind",          SYSCALL_CLASS_FD, false},
    {__NR_listen,        "listen",        SYSCALL_CLASS_FD, false},
    {__NR_dup,           "dup",           SYSCALL_CLASS_FD, false},
    {__NR_dup2,          "dup2",          SYSCALL_CLASS_FD, false},
#ifdef __NR_dup3
    {__NR_dup3,          "dup3",          SYSCALL_CLASS_FD, false},
#endif
    {__NR_pipe,          "pipe",          SYSCALL_CLASS_FD, false},
#ifdef __NR_pipe2
    {__NR_pipe2,         "pipe2",         SYSCALL_CLASS_FD, false},
#endif
    
    /* ===== SYSCALL_CLASS_MEM - Memory Management ===== */
    {__NR_mmap,          "mmap",          SYSCALL_CLASS_MEM, false},
    {__NR_munmap,        "munmap",        SYSCALL_CLASS_MEM, false},
    {__NR_mprotect,      "mprotect",      SYSCALL_CLASS_MEM, false},
    {__NR_brk,           "brk",           SYSCALL_CLASS_MEM, false},
#ifdef __NR_mremap
    {__NR_mremap,        "mremap",        SYSCALL_CLASS_MEM, false},
#endif
    {__NR_madvise,       "madvise",       SYSCALL_CLASS_MEM, false},
    
    /* ===== SYSCALL_CLASS_INFO - Information Queries ===== */
    {__NR_stat,          "stat",          SYSCALL_CLASS_INFO, false},
    {__NR_fstat,         "fstat",         SYSCALL_CLASS_INFO, false},
    {__NR_lstat,         "lstat",         SYSCALL_CLASS_INFO, false},
#ifdef __NR_newfstatat
    {__NR_newfstatat,    "newfstatat",    SYSCALL_CLASS_INFO, false},
#endif
    {__NR_getpid,        "getpid",        SYSCALL_CLASS_INFO, false},
    {__NR_getuid,        "getuid",        SYSCALL_CLASS_INFO, false},
    {__NR_geteuid,       "geteuid",       SYSCALL_CLASS_INFO, false},
    {__NR_getgid,        "getgid",        SYSCALL_CLASS_INFO, false},
    {__NR_getegid,       "getegid",       SYSCALL_CLASS_INFO, false},
    {__NR_uname,         "uname",         SYSCALL_CLASS_INFO, false},
    {__NR_getcwd,        "getcwd",        SYSCALL_CLASS_INFO, false},
    {__NR_getdents,      "getdents",      SYSCALL_CLASS_INFO, false},
    
    /* ===== SYSCALL_CLASS_PROC - Process Management ===== */
    {__NR_fork,          "fork",          SYSCALL_CLASS_PROC, false},
#ifdef __NR_vfork
    {__NR_vfork,         "vfork",         SYSCALL_CLASS_PROC, false},
#endif
    {__NR_execve,        "execve",        SYSCALL_CLASS_PROC, false},
#ifdef __NR_execveat
    {__NR_execveat,      "execveat",      SYSCALL_CLASS_PROC, false},
#endif
    {__NR_wait4,         "wait4",         SYSCALL_CLASS_PROC, false},
#ifdef __NR_waitid
    {__NR_waitid,        "waitid",        SYSCALL_CLASS_PROC, false},
#endif
    {__NR_exit,          "exit",          SYSCALL_CLASS_PROC, false},
    {__NR_exit_group,    "exit_group",    SYSCALL_CLASS_PROC, false},
    
    /* ===== SYSCALL_CLASS_SIG - Signal Handling ===== */
    {__NR_rt_sigaction,  "rt_sigaction",  SYSCALL_CLASS_SIG, false},
    {__NR_rt_sigprocmask, "rt_sigprocmask", SYSCALL_CLASS_SIG, false},
#ifdef __NR_rt_sigreturn
    {__NR_rt_sigreturn,  "rt_sigreturn",  SYSCALL_CLASS_SIG, false},
#endif
    {__NR_kill,          "kill",          SYSCALL_CLASS_SIG, false},
#ifdef __NR_tkill
    {__NR_tkill,         "tkill",         SYSCALL_CLASS_SIG, false},
#endif
    
    /* ===== SYSCALL_CLASS_THR - Thread Management ===== */
    {__NR_clone,         "clone",         SYSCALL_CLASS_THR, false},
#ifdef __NR_sched_yield
    {__NR_sched_yield,   "sched_yield",   SYSCALL_CLASS_THR, false},
#endif
    {__NR_futex,         "futex",         SYSCALL_CLASS_THR, false},
    
    /* End marker */
    {-1, NULL, SYSCALL_CLASS_MISC, false}
};

/* ===== Implementation Functions ===== */

const syscall_info_t *rr_get_syscall_info(int syscall_nr)
{
    /* Linear search (small table, sufficient performance) */
    for (int i = 0; g_syscall_table[i].nr != -1; i++) {
        if (g_syscall_table[i].nr == syscall_nr) {
            return &g_syscall_table[i];
        }
    }
    
    /* Not found, return default info */
    static const syscall_info_t default_info = {
        -1, "unknown", SYSCALL_CLASS_MISC, false
    };
    return &default_info;
}

/**
 * @brief Determine whether to Auto Fork (Auto Fork Heuristic)
 * 
 * Core decision function for Fork Server. Called in `rr_check_auto_fork_point`.
 * Decides whether the current syscall point should be used as a new Fork Point.
 * 
 * **Strategy**:
 * - `STRICT`: Fork only on successful read marked as input (Conservative).
 * - `RELAXED`: Allow partial errors (e.g., ENOENT).
 * - `AGGRESSIVE`: Fork on any I/O class syscall (Maximize coverage).
 * - `FALLBACK`: Defer decision to upper layer logic.
 * 
 * @param syscall_nr System call number
 * @param ret Return value
 * @return true if fork should occur, false otherwise.
 */
bool rr_should_auto_fork(int syscall_nr, abi_long ret)
{
    const syscall_info_t *info = rr_get_syscall_info(syscall_nr);
    
    /*
     * Improved Fork Strategy (Supports multiple modes)
     * 
     * Mode descriptions:
     * - STRICT: Original EnvFuzz strategy (ret > 0 && is_input && class == IO)
     * - RELAXED: Allows exploratory errors (ENOENT, EACCES)
     * - AGGRESSIVE: Fork on any I/O class syscall (Recommended for testing)
     * - FALLBACK: Handled in rr_check_auto_fork_point()
     */
    
    /* Base filter: Must be I/O class or FD class (as open/openat is followed by I/O) */
    if (info->class != SYSCALL_CLASS_IO && info->class != SYSCALL_CLASS_FD) {
        return false;  
    }
    
    /* Choose logic based on strategy */
    switch (g_rr_config.fork_strategy) {
        case RR_FORK_STRATEGY_STRICT:
            /* STRICT: Original EnvFuzz strategy */
            if (!info->is_input) return false;
            if (ret <= 0) return false;
            return true;
            
        case RR_FORK_STRATEGY_RELAXED:
            /* RELAXED: Allows exploratory errors like ENOENT/EACCES */
            if (!info->is_input) return false;
            if (ret > 0) return true;  // Success
            // Allow specific exploratory errors
            if (ret == -2 || ret == -13) return true;  // ENOENT or EACCES
            return false;
            
        case RR_FORK_STRATEGY_AGGRESSIVE:
            /* AGGRESSIVE: Any I/O class syscall forks (Recommended) */
            // Does not check direction or return value
            return true;
            
        case RR_FORK_STRATEGY_FALLBACK:
            /* FALLBACK: Handled in check_auto_fork_point */
            if (!info->is_input) return false;
            if (ret > 0) return true;  // Success preferred
            return false;  // Failure waits for fallback handling
            
        default:
            /* Default to AGGRESSIVE */
            return true;
    }
}

const char *rr_get_syscall_class_name(syscall_class_t class)
{
    switch (class) {
        case SYSCALL_CLASS_MISC: return "MISC";
        case SYSCALL_CLASS_FD:   return "FD";
        case SYSCALL_CLASS_IO:   return "IO";
        case SYSCALL_CLASS_INFO: return "INFO";
        case SYSCALL_CLASS_MEM:  return "MEM";
        case SYSCALL_CLASS_SIG:  return "SIG";
        case SYSCALL_CLASS_THR:  return "THR";
        case SYSCALL_CLASS_PROC: return "PROC";
        default: return "UNKNOWN";
    }
}

