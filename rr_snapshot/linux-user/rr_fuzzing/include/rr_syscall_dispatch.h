/**
 * Syscall Dispatch Optimization Module
 * Uses function pointer tables and ID mapping to replace expensive string comparisons.
 */

#ifndef RR_SYSCALL_DISPATCH_H
#define RR_SYSCALL_DISPATCH_H

#include "rr_framework.h"
#include "rr_syscallparser.h"

/* Syscall type enumeration */
typedef enum {
    SYSCALL_TYPE_UNKNOWN = 0,
    SYSCALL_TYPE_FILE_IO,
    SYSCALL_TYPE_NETWORK,
    SYSCALL_TYPE_PROCESS,
    SYSCALL_TYPE_MEMORY,
    SYSCALL_TYPE_TIME,
    SYSCALL_TYPE_SIGNAL,
    SYSCALL_TYPE_SYSTEM_INFO,
    SYSCALL_TYPE_MAX
} syscall_type_t;

/* Syscall importance level */
typedef enum {
    SYSCALL_IMPORTANCE_CRITICAL = 0,
    SYSCALL_IMPORTANCE_IMPORTANT,
    SYSCALL_IMPORTANCE_OPTIONAL,
    SYSCALL_IMPORTANCE_ENVIRONMENT,
    SYSCALL_IMPORTANCE_MAX
} syscall_importance_t;

/* Syscall handler structure */
typedef struct rr_syscall_handler {
    const char *name;
    int syscall_nr;
    syscall_type_t type;
    syscall_importance_t importance;
    
    /* Handler function pointers */
    void (*apply_args)(rr_strace_record_t *record, abi_long *args);
    void (*apply_fd_mapping)(const char *syscall_name, abi_long *args);
    void (*post_hook)(rr_strace_record_t *record, abi_long ret, abi_long *args);
    
    /* Flags */
    bool needs_fd_mapping;
    bool needs_addr_mapping;
    bool is_fd_syscall;
} rr_syscall_handler_t;

/* Fast lookup structure */
typedef struct {
    int syscall_nr;
    rr_syscall_handler_t *handler;
} syscall_lookup_entry_t;

/* Public interface */
int rr_syscall_dispatch_init(void);
void rr_syscall_dispatch_cleanup(void);

rr_syscall_handler_t* rr_get_syscall_handler(int syscall_nr);
rr_syscall_handler_t* rr_get_syscall_handler_by_name(const char *name);

const char* rr_get_syscall_name_fast(int syscall_nr);
syscall_type_t rr_get_syscall_type(int syscall_nr);
syscall_importance_t rr_get_syscall_importance(int syscall_nr);

/* Optimized handler functions */
void rr_apply_syscall_args_optimized(rr_strace_record_t *record, abi_long *args);
void rr_apply_fd_mapping_optimized(int syscall_nr, abi_long *args);
void rr_syscall_post_hook_optimized(int syscall_nr, rr_strace_record_t *record, 
                                    abi_long ret, abi_long *args);

#endif /* RR_SYSCALL_DISPATCH_H */
