/*
 * RR-Fuzz Dynamic Trace - Real-time Tree Visualization
 * Sends syscall and Fork events to Python.
 */

#ifndef RR_DYNAMIC_TRACE_H
#define RR_DYNAMIC_TRACE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/* Forward declaration - avoid circular dependency */
typedef struct CPUArchState CPUArchState;

/* Message types */
typedef enum {
    RR_DYN_MSG_SYSCALL_ENTER = 0,
    RR_DYN_MSG_SYSCALL_EXIT = 1,
    RR_DYN_MSG_FORK = 2,
    RR_DYN_MSG_EXEC = 3,
    RR_DYN_MSG_EXIT = 4,
    RR_DYN_MSG_INIT = 5,
    RR_DYN_MSG_CLEANUP = 6,
    RR_DYN_MSG_ITERATION = 7    /* Iteration start event */
} rr_dynamic_msg_type_t;

/* Syscall information */
typedef struct {
    uint32_t index;         /* Trace index */
    int32_t syscall_nr;     /* Syscall number */
    uint64_t args[8];       /* Arguments */
    int32_t retval;         /* Return value */
    uint32_t pid;           /* Process ID */
    uint32_t parent_pid;    /* Parent PID */
    uint8_t is_fuzzed;      /* Whether mutated */
    uint8_t is_entry;       /* Entry/Exit flag */
    char name[64];          /* Syscall name */
} rr_dynamic_syscall_info_t;

/* Full message structure */
typedef struct {
    rr_dynamic_msg_type_t type;
    uint32_t pid;
    uint32_t parent_pid;
    rr_dynamic_syscall_info_t syscall_info;
} rr_dynamic_trace_msg_t;

/* API Functions */
#ifdef __cplusplus
extern "C" {
#endif

/* API function declarations */
void rr_dynamic_trace_init(int write_fd);
void rr_dynamic_trace_cleanup(void);
void rr_dynamic_trace_syscall_enter(CPUArchState *env, int num, uint64_t *args, 
                                     uint32_t trace_index, uint8_t is_fuzzed);
void rr_dynamic_trace_syscall_exit(CPUArchState *env, int num, uint64_t *args, 
                                    int32_t ret, uint32_t trace_index, uint8_t is_fuzzed);
void rr_dynamic_trace_fork(uint32_t parent_pid, uint32_t child_pid, uint32_t fork_syscall_index);
void rr_dynamic_trace_iteration(uint32_t iteration_id, uint32_t pid);
void rr_dynamic_trace_exec(uint32_t pid);
void rr_dynamic_trace_exit(uint32_t pid, int exit_code);
void rr_dynamic_trace_enable_in_child(void);  /* Re-enable trace in forked child */

/* 全局变量声明 - 允许直接访问 */
extern int g_dynamic_trace_pipe_fd;
extern bool g_dynamic_trace_enabled;

#ifdef __cplusplus
}
#endif

#endif /* RR_DYNAMIC_TRACE_H */
