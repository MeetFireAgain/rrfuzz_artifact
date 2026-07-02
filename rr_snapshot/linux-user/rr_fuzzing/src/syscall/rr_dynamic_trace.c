/*
 * RR-Fuzz Dynamic Trace Implementation
 * Sends real-time syscall and Fork events to Python for tree visualization.
 */

/* RR_DEBUG must be defined before includes */
#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "qemu/osdep.h"  // Must be included first
#include "rr_dynamic_trace.h"
#include "rr_framework.h"
#include "rr_syscall_dispatch.h"  /* for rr_get_syscall_name_fast */
#include "rr_constants.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Global trace pipe */
int g_dynamic_trace_pipe_fd = -1;  // Visible to other files
bool g_dynamic_trace_enabled = false;  // Visible to other files

/**
 * @brief Initialize the dynamic trace system.
 * 
 * Establishes a communication pipe with the Python side (Tree Visualizer).
 * 
 * **Features**:
 * 1. Automatically adjusts pipe buffer size to 1MB to prevent blocking on high-frequency messages.
 * 2. Sets SIGPIPE to be ignored to prevent process exit if the reader disconnects.
 * 3. Sends an INIT handshake message.
 * 
 * @param write_fd File descriptor of the write end of the pipe.
 */
void rr_dynamic_trace_init(int write_fd) {
    RR_INFO("=== Dynamic Trace Init START ===");
    RR_INFO("  write_fd = %d", write_fd);
    
    g_dynamic_trace_pipe_fd = write_fd;
    g_dynamic_trace_enabled = (write_fd >= 0);
    
    // P0 Fix: Increase pipe buffer to 1MB (from default ~64KB)
    if (g_dynamic_trace_enabled) {
        int pipe_size = 1024 * 1024;  // 1MB
        if (fcntl(write_fd, F_SETPIPE_SZ, pipe_size) < 0) {
            RR_WARN("  Failed to increase pipe buffer: %s (errno=%d)", strerror(errno), errno);
            RR_WARN("  Will use default pipe size (~64KB)");
        } else {
            int actual_size = fcntl(write_fd, F_GETPIPE_SZ);
            RR_INFO("  Pipe buffer size: %d bytes (requested %d)", actual_size, pipe_size);
        }
        
        // P0 Fix: Ignore SIGPIPE (prevent process from being killed if Visualizer disconnects)
        signal(SIGPIPE, SIG_IGN);
        RR_INFO("  SIGPIPE handler set to SIG_IGN");
    }
    
    RR_INFO("  g_dynamic_trace_enabled = %d", g_dynamic_trace_enabled);
    
    if (g_dynamic_trace_enabled) {
        /* Send initialization message */
        rr_dynamic_trace_msg_t msg = {
            .type = RR_DYN_MSG_INIT,
            .pid = getpid(),
            .parent_pid = 0
        };
        
        RR_INFO("  Attempting to write INIT message (%zu bytes)", sizeof(msg));
        errno = 0;
        ssize_t written = write(g_dynamic_trace_pipe_fd, &msg, sizeof(msg));
        
        RR_INFO("  write() returned: %zd", written);
        if (written < 0) {
            RR_WARN("  errno = %d (%s)", errno, strerror(errno));
            RR_WARN("  ❌ INIT message send FAILED - disabling dynamic trace");
            g_dynamic_trace_enabled = false;
        } else if (written != sizeof(msg)) {
            RR_WARN("  ⚠️  Partial write: %zd/%zu bytes", written, sizeof(msg));
            g_dynamic_trace_enabled = false;
        } else {
            RR_INFO("  ✅ INIT message sent successfully (%zd bytes)", written);
        }
    }
    
    RR_INFO("=== Dynamic Trace Init END (enabled=%d) ===", g_dynamic_trace_enabled);
}

void rr_dynamic_trace_cleanup(void) {
    if (!g_dynamic_trace_enabled) return;
    
    /* Send cleanup message */
    rr_dynamic_trace_msg_t msg = {
        .type = RR_DYN_MSG_CLEANUP,
        .pid = getpid(),
        .parent_pid = 0
    };
    if (write(g_dynamic_trace_pipe_fd, &msg, sizeof(msg)) < 0) {
        /* Ignore cleanup errors */
    }
    
    if (g_dynamic_trace_pipe_fd >= 0) {
        close(g_dynamic_trace_pipe_fd);
        g_dynamic_trace_pipe_fd = -1;
    }
    g_dynamic_trace_enabled = false;
    
    RR_INFO("Dynamic trace cleanup completed");
}

static inline void send_trace_msg(rr_dynamic_trace_msg_t *msg) {
    if (!g_dynamic_trace_enabled || g_dynamic_trace_pipe_fd < 0) {
        RR_VERBOSE("send_trace_msg: skipped (enabled=%d, fd=%d)", g_dynamic_trace_enabled, g_dynamic_trace_pipe_fd);
        return;
    }
    
    errno = 0;
    ssize_t written = write(g_dynamic_trace_pipe_fd, msg, sizeof(rr_dynamic_trace_msg_t));
    if (written != sizeof(rr_dynamic_trace_msg_t)) {
        // P0 Fix: Handle error types instead of permanently disabling trace.
        if (written < 0) {
            // write() returned -1, check errno
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Pipe full, drop this message (do not disable, continue trying)
                RR_VERBOSE("Dynamic trace pipe full (EAGAIN), message dropped (type=%u)", msg->type);
            } else if (errno == EPIPE) {
                // Visualizer disconnected; disable trace.
                RR_WARN("Dynamic trace pipe broken (EPIPE), disabling trace");
                g_dynamic_trace_enabled = false;
            } else {
                // Other error; log and continue.
                RR_WARN("Dynamic trace write failed: errno=%d (%s), continuing anyway", 
                        errno, strerror(errno));
            }
        } else {
            // Partial write (written > 0 but < sizeof); rare for pipes.
            RR_WARN("Dynamic trace partial write: %zd/%zu bytes, message may be corrupted", 
                    written, sizeof(rr_dynamic_trace_msg_t));
            // Do not disable, continue trying
        }
    } else {
        RR_VERBOSE("send_trace_msg: wrote %zd bytes (type=%u)", written, msg->type);
    }
}

/**
 * @brief Send syscall entry event.
 * 
 * Called when QEMU is about to execute a syscall.
 * 
 * **Sent Data**:
 * - Syscall Number & Name
 * - Arguments (Raw values)
 * - Trace Index (Associated with the trace file)
 * - Fuzzing Status (Whether mutated)
 * 
 * @param env CPU environment
 * @param num Syscall number
 * @param args Argument array
 * @param trace_index Index in the trace
 * @param is_fuzzed Whether modified by the Fuzz Engine
 */
void rr_dynamic_trace_syscall_enter(CPUArchState *env, int num, uint64_t *args,
                                     uint32_t trace_index, uint8_t is_fuzzed) {
    if (!g_dynamic_trace_enabled) {
        RR_VERBOSE("Dynamic trace syscall_enter skipped: not enabled");
        return;
    }
    
    RR_VERBOSE("Dynamic trace syscall_enter: num=%d, index=%u", num, trace_index);
    
    /* Explicitly initialize entire structure to 0 */
    rr_dynamic_trace_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    
    msg.type = RR_DYN_MSG_SYSCALL_ENTER;
    msg.pid = getpid();
    msg.parent_pid = 0;
    
    msg.syscall_info.index = trace_index;
    msg.syscall_info.syscall_nr = num;
    msg.syscall_info.is_fuzzed = is_fuzzed;
    msg.syscall_info.is_entry = 1;
    msg.syscall_info.pid = getpid();
    
    /* Copy arguments */
    if (args) {
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
            msg.syscall_info.args[i] = args[i];
        }
    }
    
    /* Get syscall name - try dispatch first, then built-in table on failure */
    const char *name = rr_get_syscall_name_fast(num);
    if (!name) {
        /* Built-in common syscall name table (consistency with rr_main.c) */
        switch(num) {
            case 0: name = "read"; break;
            case 1: name = "write"; break;
            case 2: name = "open"; break;
            case 3: name = "close"; break;
            case 4: name = "stat"; break;
            case 5: name = "fstat"; break;
            case 9: name = "mmap"; break;
            case 10: name = "mprotect"; break;
            case 11: name = "munmap"; break;
            case 12: name = "brk"; break;
            case 16: name = "ioctl"; break;
            case 17: name = "pread64"; break;
            case 21: name = "access"; break;
            case 39: name = "getpid"; break;
            case 63: name = "uname"; break;
            case 158: name = "arch_prctl"; break;
            case 217: name = "getdents64"; break;
            case 218: name = "set_tid_address"; break;
            case 231: name = "exit_group"; break;
            case 257: name = "openat"; break;
            case 262: name = "newfstatat"; break;
            case 273: name = "set_robust_list"; break;
            case 302: name = "prlimit64"; break;
            case 318: name = "getrandom"; break;
            case 334: name = "rseq"; break;
            default: name = NULL; break;
        }
    }
    
    if (name) {
        strncpy(msg.syscall_info.name, name, sizeof(msg.syscall_info.name) - 1);
        msg.syscall_info.name[sizeof(msg.syscall_info.name) - 1] = '\0';
    } else {
        snprintf(msg.syscall_info.name, sizeof(msg.syscall_info.name), "syscall_%d", num);
    }
    
    /* Debug: Validate message data */
    RR_INFO("ENTER msg: type=%u, pid=%u, index=%u, nr=%d, name='%s'",
            msg.type, msg.pid, msg.syscall_info.index, msg.syscall_info.syscall_nr, msg.syscall_info.name);
    
    send_trace_msg(&msg);
}

void rr_dynamic_trace_syscall_exit(CPUArchState *env, int num, uint64_t *args,
                                    int32_t ret, uint32_t trace_index, uint8_t is_fuzzed) {
    if (!g_dynamic_trace_enabled) return;
    
    /* Explicitly initialize entire structure to 0 */
    rr_dynamic_trace_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    
    msg.type = RR_DYN_MSG_SYSCALL_EXIT;
    msg.pid = getpid();
    msg.parent_pid = 0;
    
    msg.syscall_info.index = trace_index;
    msg.syscall_info.syscall_nr = num;
    msg.syscall_info.retval = ret;
    msg.syscall_info.is_fuzzed = is_fuzzed;
    msg.syscall_info.is_entry = 0;
    msg.syscall_info.pid = getpid();
    
    /* Copy arguments */
    if (args) {
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
            msg.syscall_info.args[i] = args[i];
        }
    }
    
    /* Get syscall name - try dispatch first, then built-in table on failure */
    const char *name = rr_get_syscall_name_fast(num);
    if (!name) {
        /* Built-in common syscall name table (consistency with syscall_enter) */
        switch(num) {
            case 0: name = "read"; break;
            case 1: name = "write"; break;
            case 2: name = "open"; break;
            case 3: name = "close"; break;
            case 4: name = "stat"; break;
            case 5: name = "fstat"; break;
            case 9: name = "mmap"; break;
            case 10: name = "mprotect"; break;
            case 11: name = "munmap"; break;
            case 12: name = "brk"; break;
            case 16: name = "ioctl"; break;
            case 17: name = "pread64"; break;
            case 21: name = "access"; break;
            case 39: name = "getpid"; break;
            case 63: name = "uname"; break;
            case 158: name = "arch_prctl"; break;
            case 217: name = "getdents64"; break;
            case 218: name = "set_tid_address"; break;
            case 231: name = "exit_group"; break;
            case 257: name = "openat"; break;
            case 262: name = "newfstatat"; break;
            case 273: name = "set_robust_list"; break;
            case 302: name = "prlimit64"; break;
            case 318: name = "getrandom"; break;
            case 334: name = "rseq"; break;
            default: name = NULL; break;
        }
    }
    
    if (name) {
        strncpy(msg.syscall_info.name, name, sizeof(msg.syscall_info.name) - 1);
        msg.syscall_info.name[sizeof(msg.syscall_info.name) - 1] = '\0';
    } else {
        snprintf(msg.syscall_info.name, sizeof(msg.syscall_info.name), "syscall_%d", num);
    }
    
    send_trace_msg(&msg);
}

/**
 * @brief Send Fork event.
 * 
 * Called when Fork Server creates a new process for process tree visualization.
 * 
 * @param parent_pid Parent process PID
 * @param child_pid Child process PID
 * @param fork_syscall_index Syscall index triggering the Fork
 */
void rr_dynamic_trace_fork(uint32_t parent_pid, uint32_t child_pid, uint32_t fork_syscall_index) {
    if (!g_dynamic_trace_enabled) {
        /* fprintf(stderr, "[RR-DYNAMIC-TRACE] ⚠️  FORK message NOT sent: dynamic trace disabled\\n\"); */
        return;
    }

    rr_dynamic_trace_msg_t msg = {
        .type = RR_DYN_MSG_FORK,
        .pid = child_pid,
        .parent_pid = parent_pid
    };

    msg.syscall_info.index = fork_syscall_index;

    send_trace_msg(&msg);

    // Enhanced debug output
    fprintf(stderr, "[RR-DYNAMIC-TRACE] 🍴 FORK message sent: parent=%u -> child=%u @ syscall[%u]\n",
            parent_pid, child_pid, fork_syscall_index);
    RR_VERBOSE("Dynamic trace: fork %u -> %u @ syscall[%u]", parent_pid, child_pid, fork_syscall_index);
}

/* Send iteration start event */
void rr_dynamic_trace_iteration(uint32_t iteration_id, uint32_t pid) {
    if (!g_dynamic_trace_enabled) return;
    
    rr_dynamic_trace_msg_t msg = {
        .type = RR_DYN_MSG_ITERATION,
        .pid = pid,
        .parent_pid = 0
    };
    
    /* Use syscall_info.index to pass iteration_id */
    msg.syscall_info.index = iteration_id;
    
    send_trace_msg(&msg);
    
    RR_VERBOSE("Dynamic trace: iteration %u started (pid=%u)", iteration_id, pid);
}

void rr_dynamic_trace_exec(uint32_t pid) {
    if (!g_dynamic_trace_enabled) return;
    
    rr_dynamic_trace_msg_t msg = {
        .type = RR_DYN_MSG_EXEC,
        .pid = pid,
        .parent_pid = 0
    };
    
    send_trace_msg(&msg);
}

void rr_dynamic_trace_exit(uint32_t pid, int exit_code) {
    if (!g_dynamic_trace_enabled) return;
    
    rr_dynamic_trace_msg_t msg = {
        .type = RR_DYN_MSG_EXIT,
        .pid = pid,
        .parent_pid = 0
    };
    
    msg.syscall_info.retval = exit_code;
    
    send_trace_msg(&msg);
}

/* Re-enable dynamic trace in forked child
 * Child process inherits pipe FD; ensure g_dynamic_trace_enabled is true.
 */
void rr_dynamic_trace_enable_in_child(void) {
    RR_INFO("[CHILD-TRACE] enable_in_child called: PID=%d, current_fd=%d, current_enabled=%d", 
            getpid(), g_dynamic_trace_pipe_fd, g_dynamic_trace_enabled);
    
    if (g_dynamic_trace_pipe_fd >= 0) {
        g_dynamic_trace_enabled = true;
        RR_INFO("[CHILD-TRACE] ✅ Dynamic trace re-enabled (PID=%d, fd=%d)", 
                getpid(), g_dynamic_trace_pipe_fd);
    } else {
        RR_WARN("[CHILD-TRACE] ❌ Cannot enable: pipe fd=%d invalid", g_dynamic_trace_pipe_fd);
    }
    
    RR_INFO("[CHILD-TRACE] After enable: enabled=%d", g_dynamic_trace_enabled);
}
