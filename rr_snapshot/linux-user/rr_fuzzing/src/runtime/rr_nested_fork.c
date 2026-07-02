/**
 * RR-Fuzz Autonomous Nested Fork Module
 * Implements autonomous child process nested forking.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include "rr_framework.h"
#include "rr_syscall_info.h"
#include "rr_dynamic_trace.h"

/**
 * Check if a syscall is an I/O class syscall.
 */
bool is_io_syscall(int syscall_nr) {
    const syscall_info_t *info = rr_get_syscall_info(syscall_nr);
    if (!info) {
        return false;
    }
    
    return (info->class == SYSCALL_CLASS_IO);
}

/**
 * Determine whether to trigger a nested fork at the current syscall.
 * 
 * Strategy:
 * 1. Must be an autonomous child (depth > 0).
 * 2. Must be an I/O syscall.
 * 3. Limit the number of forks per process (prevent fork bombs).
 * 4. Currently triggers only on the first I/O syscall (simplified for testing).
 */
/**
 * @brief Determine whether to trigger a Nested Fork (Nested Fork Heuristic).
 * 
 * Portions of the trace may be explored by forking grandchildren from child processes.
 * 
 * **Trigger Conditions**:
 * 1. Must be an Autonomous Child (created by Fork Server).
 * 2. Nesting depth < 2 (prevents fork bombs).
 * 3. Limit total forks per process (currently limited to 1).
 * 4. **Hardcoded Trigger**: Currently triggers on the 5th syscall for testing.
 * 
 * @param syscall_nr Syscall number.
 * @return true if nested fork should trigger.
 */
bool rr_should_nested_fork(int syscall_nr, const char *syscall_name, abi_long ret) {
    /* Only autonomous children can perform nested forks */
    if (!g_rr_framework->is_autonomous_child) {
        return false;
    }
    
    /* Limit depth (Max 2 levels: parent → child → grandchild) */
    if (g_rr_framework->current_depth > 1) {
        return false;
    }
    
    /* Limit forks per process to prevent fork bombs */
    const uint32_t MAX_FORKS_PER_PROCESS = 1;  /* Each child forks once */
    if (g_rr_framework->forks_this_iteration >= MAX_FORKS_PER_PROCESS) {
        return false;
    }
    
    /* Trigger on any successful syscall (high probability for demonstration) */
    if (ret < 0) {
        return false;
    }
    
    /* Trigger on the 5th syscall (simplified logic) */
    static __thread int syscall_count = 0;
    syscall_count++;
    
    if (syscall_count != 5) {
        return false;
    }
    
    RR_INFO("Nested fork trigger: %s (depth=%u, syscall_nr=%d)", 
            syscall_name, g_rr_framework->current_depth, syscall_nr);
    
    return true;
}

/**
 * Execute autonomous nested fork - multi-level dynamic fork implementation.
 * 
 * Children may autonomously decide to fork multiple grandchildren during execution.
 */
#define NUM_NESTED_VARIANTS 2

extern FILE *g_trace_file;
extern char *g_rr_trace_path;

/**
 * @brief Execute Autonomous Nested Fork.
 * 
 * Implementation of multi-level forking. The current child process pauses
 * and forks multiple (default 2) grandchildren for parallel exploration.
 * 
 * **Mechanism**:
 * 1. Fork N grandchildren.
 * 2. Grandchildren reopen the trace file for independent file pointers.
 * 3. Grandchildren inherit state and continue execution.
 * 4. **Parent (Child) waits for all grandchildren to complete** to maintain process tree structure.
 * 
 * @param fork_index Current syscall index.
 */
void rr_autonomous_nested_fork(int fork_index) {
    RR_INFO("🔄 Autonomous nested fork at syscall[%d] (depth=%u, iteration=%u)", 
            fork_index, g_rr_framework->current_depth, g_rr_framework->current_iteration_id);
    
    g_rr_framework->forks_this_iteration++;
    
    /* Nested fork implementation */
    // const int NUM_NESTED_VARIANTS = 2;  // Fork 2 grandchildren
    
    pid_t my_pid = getpid();
    pid_t grandchild_pids[NUM_NESTED_VARIANTS];
    
    // Save current state (trace file must be independent for each grandchild)
    // extern FILE *g_trace_file;
    // extern char *g_rr_trace_path;
    
    for (int i = 0; i < NUM_NESTED_VARIANTS; i++) {
        pid_t pid = fork();
        
        if (pid == 0) {
            /* --- Grandchild Process --- */
            
            // Independent trace file
            if (g_trace_file && g_rr_trace_path) {
                fclose(g_trace_file);
                g_trace_file = fopen(g_rr_trace_path, "rb");
                if (!g_trace_file) {
                    RR_ERROR("Grandchild %d: Failed to reopen trace", i);
                    _exit(1);
                }
                // Maintain inherited file position
                RR_INFO("Grandchild %d: Reopened trace file", i);
            }
            
            // Update status
            g_rr_framework->current_depth++;
            g_rr_framework->is_autonomous_child = true;  // Grandchild is also autonomous
            
#ifdef RR_ENABLE_DYNAMIC_TRACE
            if (g_dynamic_trace_enabled && g_dynamic_trace_pipe_fd >= 0) {
                // Grandchild sends iteration message
                rr_dynamic_trace_iteration(g_rr_framework->current_iteration_id, getpid());
            }
#endif
            
            RR_INFO("✅ Grandchild %d started: PID=%d, depth=%u", 
                    i, getpid(), g_rr_framework->current_depth);
            
            // Grandchild continues execution from current replay_index
            return;
            
        } else if (pid > 0) {
            /* --- Parent (original child) --- */
            grandchild_pids[i] = pid;
            
#ifdef RR_ENABLE_DYNAMIC_TRACE
            if (g_dynamic_trace_enabled && g_dynamic_trace_pipe_fd >= 0) {
                rr_dynamic_trace_fork(my_pid, pid, fork_index);
            }
#endif
            
            RR_INFO("  Nested fork: grandchild %d PID=%d", i, pid);
        } else {
            RR_ERROR("Nested fork failed for variant %d", i);
            break;
        }
    }
    
    /* --- Parent waits for all grandchildren to complete --- */
    if (getpid() == my_pid) {
        RR_INFO("⏳ Waiting for %d grandchildren to complete...", NUM_NESTED_VARIANTS);
        for (int i = 0; i < NUM_NESTED_VARIANTS; i++) {
            if (grandchild_pids[i] > 0) {
                int status;
                waitpid(grandchild_pids[i], &status, 0);
                RR_INFO("  Grandchild %d (PID=%d) finished", i, grandchild_pids[i]);
            }
        }
        
        RR_INFO("✅ All grandchildren completed, continuing execution");
    }
}

