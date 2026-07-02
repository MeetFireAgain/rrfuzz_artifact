/**
 * RR-Fuzz Fork Server Module
 * Implements high-speed fuzzing via fork server mechanism with syscall-based fork points.
 * 
 * Features:
 * - Syscall-based fork points (e.g., "openat", "read")
 * - Path pattern matching support
 * - Intelligent fork point detection with automated P_IO classification
 */

/* Ensure RR_DEBUG is defined for debug logging */
#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include <sys/wait.h>
#include <signal.h>
#include <fnmatch.h>
#include <unistd.h>
#include <fcntl.h>
#include "rr_framework.h"
#include "rr_syscall_tree.h"    /* rr_tree_export_json() for 'T' command */
#include "rr_constants.h"
#include "rr_coverage.h"
#include "rr_syscall_info.h"  /* Syscall classification */
#include "rr_dynamic_trace.h"  /* Dynamic trace API */
#include "rr_replay_strace.h"
#include "exec/cpu-common.h"   /* For current_cpu */
#include "hw/core/cpu.h"       /* For CPUState */

#include "../../../qemu.h"
#include "../../../user-internals.h"
#include "../../../syscall_defs.h"

/* Manually declare queue_tb_flush to avoid header path issues */
/* queue_tb_flush is now provided by qemu internal headers */
#if 0
void queue_tb_flush(CPUState *cpu);
#endif


extern FILE *g_trace_file;
extern char *g_rr_trace_path;
// extern void rr_reset_trace_position(void);

/* Status codes (must match Python-side definitions) */
#define STATUS_NONE          0
#define STATUS_READY         1
#define STATUS_AT_FORK_POINT 2
#define STATUS_NORMAL_EXIT   3
#define STATUS_CRASH         4
#define STATUS_OTHER_SIGNAL  5
#define STATUS_TIMEOUT       6
#define STATUS_NEED_RESTART  7  /* Parent overshot fork_point; Python must restart QEMU */

// Fork point configuration
static char *g_fork_syscall_name = NULL;      // Target syscall name
static char *g_fork_syscall_pattern = NULL;   // Path matching pattern
static bool g_at_fork_point = false;          // Flag indicating if fork point is reached

/* Global pointer to variant data for crash reporting (set in child) */
static FuzzVariant *g_child_variant_ptr = NULL;

/**
 * Host-level signal handler for child crashes
 * 
 * Captures the guest Program Counter (PC) and writes it to shared memory
 * before the process exits.
 */
static void rr_child_crash_handler(int sig)
{
    if (g_child_variant_ptr && current_cpu) {
        CPUArchState *env = (CPUArchState *)cpu_env(current_cpu);
        uint64_t pc = 0;
        
#if defined(TARGET_ARM)
        pc = env->regs[15]; // R15 is PC in ARM
#elif defined(TARGET_I386)
        pc = env->eip;
#elif defined(TARGET_MIPS)
        pc = env->active_tc.PC;
#elif defined(TARGET_PPC)
        pc = env->nip;
#elif defined(TARGET_RISCV)
        pc = env->pc;
#endif

        if (pc != 0) {
            g_child_variant_ptr->crash_pc = pc;
            // Also log to stderr for emergency triage
            fprintf(stderr, "[CORE-CRASH] Caught signal %d, guest PC = 0x%lx\n", sig, (unsigned long)pc);
        }
    }
    
    // Reset to default and re-raise to ensure core dump if enabled
    signal(sig, SIG_DFL);
    raise(sig);
}

static void rr_child_close_ipc_fds(void)
{
    if (g_rr_framework->cmd_pipe_fd >= 0) {
        close(g_rr_framework->cmd_pipe_fd);
        g_rr_framework->cmd_pipe_fd = -1;
    }
    if (g_rr_framework->status_pipe_fd >= 0) {
        close(g_rr_framework->status_pipe_fd);
        g_rr_framework->status_pipe_fd = -1;
    }
}

static void rr_child_rewind_stdin(void)
{
    if (lseek(STDIN_FILENO, 0, SEEK_SET) == (off_t)-1) {
        if (errno != ESPIPE) {
            fprintf(stderr, "[DEBUG-CHILD] Child: lseek(stdin) failed: %s\n", strerror(errno));
        }
    } else {
        fprintf(stderr, "[DEBUG-CHILD] Child: stdin rewound to 0\n");
    }
}

static int rr_child_start_replay_from_path(const char *trace_path, bool make_absolute,
                                           int variant_idx, const char *context)
{
    char resolved_path[1024];
    const char *path_to_open = trace_path;

    if (g_trace_file) {
        fclose(g_trace_file);
        g_trace_file = NULL;
    }

    if (!trace_path) {
        RR_ERROR("%s: No trace path available", context);
        return -1;
    }

    if (make_absolute && trace_path[0] != '/') {
        if (!getcwd(resolved_path, sizeof(resolved_path))) {
            RR_ERROR("%s: Failed to get current working directory", context);
            return -1;
        }
        size_t len = strlen(resolved_path);
        snprintf(resolved_path + len, sizeof(resolved_path) - len, "/%s", trace_path);
        path_to_open = resolved_path;
    }

    if (rr_start_replay(path_to_open) < 0) {
        RR_ERROR("%s: Failed to initialize replay system with path: %s", context, path_to_open);
        return -1;
    }

    RR_INFO("%s %d: Reopened trace file independently", context, variant_idx);
    return 0;
}

static int rr_child_reload_variant_instructions(int variant_idx)
{
    if (!g_rr_framework->shared_memory) {
        RR_WARN("Child %d: No shared memory available for instruction loading", variant_idx);
        return -1;
    }

    RR_INFO("Child %d: Reloading fuzz instructions from shared memory", variant_idx);
    if (rr_fuzz_load_from_shared_memory(g_rr_framework->shared_memory, variant_idx) < 0) {
        RR_ERROR("Child %d: Failed to reload fuzz instructions!", variant_idx);
        return -1;
    }

    RR_INFO("Child %d: Reloaded %zu fuzz instructions", variant_idx, g_instruction_count);
    return 0;
}

static void rr_child_install_crash_handlers(FuzzVariant *variant)
{
    g_child_variant_ptr = variant;
    if (g_child_variant_ptr) {
        g_child_variant_ptr->crash_pc = 0;
    }

    signal(SIGSEGV, rr_child_crash_handler);
    signal(SIGBUS, rr_child_crash_handler);
    signal(SIGILL, rr_child_crash_handler);
    signal(SIGABRT, rr_child_crash_handler);
    signal(SIGFPE, rr_child_crash_handler);
}

static void rr_classify_wait_status(int status, int *result_status,
                                    int *exit_code, int *signal_number)
{
    *result_status = STATUS_NORMAL_EXIT;
    *exit_code = 0;
    *signal_number = 0;

    if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
        if (*exit_code == 134 || *exit_code == 139 || *exit_code == 135 || *exit_code == 132) {
            *result_status = STATUS_CRASH;
        }
        return;
    }

    if (WIFSIGNALED(status)) {
        *signal_number = WTERMSIG(status);
        if (*signal_number == SIGSEGV || *signal_number == SIGABRT ||
            *signal_number == SIGBUS || *signal_number == SIGILL ||
            *signal_number == SIGFPE) {
            *result_status = STATUS_CRASH;
        } else {
            *result_status = STATUS_OTHER_SIGNAL;
        }
    }
}

/**
 * Reset fork point state (used for new process initialization)
 */
void rr_reset_fork_point(void)
{
    g_at_fork_point = false;
    RR_VERBOSE("Reset fork point state for new process");
}

/**
 * @brief Initialize and start the Fork Server
 * 
 * Configures the target fork point (syscall-based or path pattern).
 * Sends READY status to Conductor and enters the fork server loop.
 * 
 * **Auto-detection Mode**:
 * If syscall_name is NULL, use heuristics to select a fork point (usually the first blocking IO).
 * 
 * @param syscall_name Target syscall name (e.g., "openat"), NULL for auto-detection
 * @param pattern Path pattern (e.g., "/target/config*") for file path filtering
 * @return int 0 on success, -1 on failure
 */
int rr_start_fork_server(const char *syscall_name, const char *pattern)
{
    fprintf(stderr, "[DEBUG-FORK] rr_start_fork_server entered\n");
    fflush(stderr);
    RR_VERBOSE("Starting Fork Server initialization");

    if (!rr_framework_enabled()) {
        fprintf(stderr, "[DEBUG-FORK] Framework NOT enabled! Returning -1\n");
        RR_ERROR("Cannot start Fork Server: framework not enabled");
        return -1;
    }
    fprintf(stderr, "[DEBUG-FORK] Framework enabled. Proceeding...\n");

    // Auto-detection mode setup
    if (syscall_name) {
        g_fork_syscall_name = strdup(syscall_name);
        RR_INFO("Fork Server: target syscall = %s", syscall_name);
    } else {
        g_fork_syscall_name = NULL;
        RR_INFO("Fork Server: AUTO-DETECTION mode (P_IO syscalls)");
    }

    if (pattern) {
        g_fork_syscall_pattern = strdup(pattern);
        RR_INFO("Fork Server: path pattern = %s", pattern);
    } else {
        g_fork_syscall_pattern = NULL;
        RR_INFO("Fork Server: no path pattern (auto-detection)");
    }

    RR_INFO("RR Fork Server Loop Started (PID=%d)", getpid());
    RR_INFO("Pipe FDs: CMD=%d, STATUS=%d", g_rr_framework->cmd_pipe_fd, g_rr_framework->status_pipe_fd);

    g_rr_framework->fork_server_active = true;
    g_rr_framework->fork_server_entered = true; // Mark as entered to prevent re-entry in rr_do_syscall
    fprintf(stderr, "[DEBUG-FORK] Set active=true. Sending status...\n");
    fflush(stderr);

    RR_INFO("Fork Server started with syscall-based fork point");
    RR_VERBOSE("Fork Server state: active=%s, syscall=%s, pattern=%s",
               g_rr_framework->fork_server_active ? "true" : "false", 
               g_fork_syscall_name ? g_fork_syscall_name : "none",
               g_fork_syscall_pattern ? g_fork_syscall_pattern : "none");

    /* Send Ready status to Conductor; loop handles subsequent commands */
    RR_IPC_TRACE("Sending Ready status to Conductor");
    if (rr_ipc_send_status(1) < 0) { // 1 = Ready
        fprintf(stderr, "[DEBUG-FORK] Failed to send status!\n");
        RR_WARN("Failed to send Ready status");
        g_rr_framework->fork_server_active = false;
        return -1;
    }
    
    RR_INFO("Fork server initialized, ready to receive commands in fork_server_loop()");
    fprintf(stderr, "[DEBUG-FORK] Status sent. Entering fork_server_loop() immediately...\n");
    fflush(stderr);

    /* 🔥 CRITICAL FIX: Enter Loop Immediately! */
    int loop_ret = rr_fork_server_loop();
    
    if (loop_ret == 0) {
        /* Parent Exit / Loop Finished -- Do not force exit process, let main loop decide */
        RR_INFO("Fork Server Loop returned 0 (shutdown). Returning to emulator loop.");
        return 0;
    } else if (loop_ret == 2) {
        /* Advance State */
        RR_INFO("Fork Server Loop returned 2 (Advance). Returning to emulator loop.");
        return 0;
    } else {
        /* Child Resume or Error or Quit Command */
        RR_INFO("Fork Server Loop returned %d. Returning to emulator loop.", loop_ret);
        return 0;
    }
}

/**
 * Stop Fork Server
 */
void rr_stop_fork_server(void)
{
    if (!g_rr_framework) {
        return;
    }

    g_rr_framework->fork_server_active = false;
    g_at_fork_point = false;

    /* If child is running, terminate and clean up */
    if (g_rr_framework->child_pid > 0) {
        kill(g_rr_framework->child_pid, SIGTERM);
        waitpid(g_rr_framework->child_pid, NULL, 0);
        g_rr_framework->child_pid = 0;
    }

    /* Clear configuration */
    if (g_fork_syscall_name) {
        free(g_fork_syscall_name);
        g_fork_syscall_name = NULL;
    }
    if (g_fork_syscall_pattern) {
        free(g_fork_syscall_pattern);
        g_fork_syscall_pattern = NULL;
    }

    RR_LOG("Fork Server stopped");
}

/**
 * Extract path argument from system call
 * 
 * @param env CPU architecture state for memory access
 * @param syscall_name System call name
 * @param args System call arguments
 * @return Extracted path string (caller must free), NULL on failure
 */
static char *extract_path_from_syscall(CPUArchState *env, const char *syscall_name, const abi_long *args)
{
    if (!syscall_name || !args) {
        return NULL;
    }

    target_ulong path_addr = 0;
    
    // Determine path parameter index based on syscall type
    if (strcmp(syscall_name, "openat") == 0 || strcmp(syscall_name, "newfstatat") == 0) {
        path_addr = args[1];  // openat(dirfd, pathname, ...)
    } else if (strcmp(syscall_name, "open") == 0 || strcmp(syscall_name, "access") == 0) {
        path_addr = args[0];  // open(pathname, ...)
    } else {
        return NULL;  // Unsupported syscall
    }

    if (path_addr == 0) {
        return NULL;
    }

    /* Directly read path string from guest memory */
    if (!env) {
        RR_WARN("Cannot extract path without CPU env");
        return NULL;
    }
    
    /* Read string (max 4KB) from guest memory */
    char path_buffer[4096];
    size_t len = 0;
    
    while (len < sizeof(path_buffer) - 1) {
        uint8_t byte;
        if (cpu_memory_rw_debug(env_cpu(env), path_addr + len, &byte, 1, 0) != 0) {
            break; // Memory access failed
        }
        if (byte == 0) {
            break; // End of string
        }
        path_buffer[len++] = byte;
    }
    path_buffer[len] = '\0';
    
    if (len == 0) {
        return NULL;
    }
    
    return strdup(path_buffer);
}

/**
 * @brief Detect if fork point is reached
 * 
 * Evaluates current syscall against fork configuration.
 * 
 * **Matching Logic**:
 * 1. Match syscall name.
 * 2. Match path pattern (if configured).
 * 
 * On match:
 * - Set g_at_fork_point = true.
 * - Send STATUS_AT_FORK_POINT (2) to Conductor.
 * - Pulse execution to allow Loop to take control.
 * 
 * @param env CPU architecture state
 * @param syscall_nr Target syscall number
 * @param syscall_name Target syscall name
 * @param args Target syscall arguments
 * @return true if fork point is reached, false otherwise
 */
bool rr_check_fork_point(CPUArchState *env, int syscall_nr, const char *syscall_name, const abi_long *args)
{
    if (!g_rr_framework->fork_server_active) {
        return false;
    }

    // If already at fork point, return true
    if (g_at_fork_point) {
        return true;
    }

    // If syscall name is not configured, disable detection (compatibility mode)
    if (!g_fork_syscall_name) {
        RR_WARN("No fork syscall configured, fork point detection disabled");
        return false;
    }

    // Check if syscall name matches
    if (!syscall_name || strcmp(syscall_name, g_fork_syscall_name) != 0) {
        return false;
    }

    RR_VERBOSE("Found target syscall: %s", syscall_name);

    // Match based on syscall name if no path pattern is provided
    if (!g_fork_syscall_pattern) {
        g_at_fork_point = true;
        RR_INFO("Reached fork point: %s (no path pattern)", syscall_name);
        
        /* Notify Conductor that fork point is reached */
        RR_IPC_TRACE("Sending At Fork Point status");
        if (rr_ipc_send_status(2) < 0) { // 2 = At Fork Point
            RR_WARN("Failed to send At Fork Point status");
        }
        
        return true;
    }

    // Match based on path if pattern is provided
    char *path = extract_path_from_syscall(env, syscall_name, args);
    if (!path) {
        RR_VERBOSE("Could not extract path from %s, skipping pattern match", syscall_name);
        return false;
    }

    // Use fnmatch for pattern matching
    int match_result = fnmatch(g_fork_syscall_pattern, path, FNM_PATHNAME);
    free(path);

    if (match_result == 0) {
        // Successful match
        g_at_fork_point = true;
        RR_INFO("Reached fork point: %s matching pattern '%s'", 
               syscall_name, g_fork_syscall_pattern);
        
        /* Notify Conductor that fork point is reached */
        RR_IPC_TRACE("Sending At Fork Point status");
        if (rr_ipc_send_status(2) < 0) { // 2 = At Fork Point
            RR_WARN("Failed to send At Fork Point status");
        }
        
        return true;
    } else {
        RR_VERBOSE("Path pattern '%s' did not match, continuing...", g_fork_syscall_pattern);
        return false;
    }
}

/**
 * @brief Fork Server Main Loop
 * 
 * Handles instructions from Python Conductor when reaching a fork point.
 * Commands are received via pipe; complex data exchanged via SHM.
 * 
 * **Commands**:
 * - **'F' (Fork)**: Standard Persistent Mode execution.
 * - **'B' (Batch Fork)**: Concurrent execution of multiple variants.
 * - **'C' (Checkpoint Fork)**: Mid-point fork for deep path fuzzing.
 * - **'E' (Baseline)**: Baseline execution without mutations for coverage reference.
 * 
 * @return int 
 *         - 1: Child process (resume execution)
 *         - 0: Parent process shutdown
 */
int rr_fork_server_loop(void)
{
    fprintf(stderr, "[DEBUG-FORK-LOOP] Entered. active=%d\n", g_rr_framework->fork_server_active);
    fflush(stderr);

    /* 
     * Note: No longer check g_at_fork_point here since entry into this
     * loop implies fork point detection (via rr_check_auto_fork_point).
     */

    while (g_rr_framework->fork_server_active) {
        int cmd;

        /* CHECKPOINT FIX: Auto-resume logic to prevent deadlock */
        if (g_rr_framework->resume_from_checkpoint) {
            RR_INFO("🔄 Checkpoint Resume: Automatically scheduling 'C' command logic");
            g_rr_framework->resume_from_checkpoint = false;
            cmd = 'C';
        } else {
            /* Receive Conductor command - wait for non-zero command */
            cmd = 0;
            while (cmd == 0 && g_rr_framework->fork_server_active) {
                cmd = rr_ipc_receive_command();
                if (cmd == 0) {
                    g_usleep(1000); // 1ms
                }
            }
        }
        
        RR_INFO("Info: Fork server loop: processing command '%c' (%d)", cmd > 0 && cmd < 128 ? cmd : '?', cmd);

        switch (cmd) {
            // NEW: Batch fork command (for dynamic multi-path exploration)
            case 'B': // Batch fork command
                {
                    RR_INFO("Info: Batch fork command received");
                    
                    /* Read variant info from shared memory */
                    if (!g_rr_framework->shared_memory) {
                        RR_ERROR("No shared memory for batch fork");
                        rr_ipc_send_status(-1);
                        break;
                    }
                    
                    FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                    int num_variants = shm->num_variants;
                    
                    if (num_variants <= 0 || num_variants > 10) {
                        RR_WARN("Invalid num_variants: %d, using 1", num_variants);
                        num_variants = 1;
                    }
                    
                    RR_INFO("Batch fork: %d variants", num_variants);

                    /* Reset coverage BEFORE forking: child(ren) write fresh data; Python reads
                     * after the last rr_ipc_send_status() with no risk of being wiped. */
                    rr_coverage_reset();

                    /* Batch fork multiple child processes */
                    pid_t child_pids[RR_MAX_VARIANTS];
                    memset(child_pids, 0, sizeof(child_pids));
                    
                    for (int variant_idx = 0; variant_idx < num_variants; variant_idx++) {
                        /* Load variant mutations into the global instruction array */
                        FuzzVariant *variant = &shm->variants[variant_idx];
                        size_t count = variant->instruction_count;
                        if (count > RR_FUZZ_MAX_INSTRUCTIONS) count = RR_FUZZ_MAX_INSTRUCTIONS;
                        g_instruction_count = count;
                        
                        memcpy(g_fuzz_instructions, variant->instructions,
                               sizeof(FuzzInstruction) * g_instruction_count);
                        
                        /* Fork child process */
                        pid_t pid = fork();
                        
                        if (pid == 0) {
                            /* ═══ Child Process ═══ */
                            
                            rr_child_rewind_stdin();
                            rr_child_close_ipc_fds();
                            
                            /* Reset trace state */
                            RR_INFO("Child variant %d: Re-opening trace", variant_idx);
                            rr_child_start_replay_from_path(g_rr_trace_path, false, variant_idx, "Child");

                            if (g_current_record) {
                                rr_record_dispose(g_current_record);
                                g_current_record = NULL;
                            }

                            /* Fast-forward trace file to fork_point (same as 'C' command fix).
                             * After reopening the trace the file pointer is at the beginning,
                             * but the CPU state is already at fork_point.  We must advance the
                             * file pointer so that the first syscall the child executes reads
                             * the correct record (index >= fork_point), not record 0. */
                            {
                                uint32_t b_fork_point = shm->fork_point;
                                if (b_fork_point > 0) {
                                    RR_INFO("Child variant %d: Fast-forwarding trace to fork_point %u",
                                            variant_idx, b_fork_point);
                                    syscall_record_t *tmp_rec = NULL;
                                    int seek_count = 0;
                                    while (1) {
                                        tmp_rec = read_next_record();
                                        if (!tmp_rec) {
                                            RR_ERROR("Child %d: EOF before reaching fork_point %u (skipped %d)",
                                                     variant_idx, b_fork_point, seek_count);
                                            break;
                                        }
                                        if (tmp_rec->index >= b_fork_point) {
                                            g_current_record = tmp_rec;
                                            RR_INFO("Child %d: Kept record index=%u (>= fork_point=%u)",
                                                    variant_idx, tmp_rec->index, b_fork_point);
                                            break;
                                        }
                                        rr_record_dispose(tmp_rec);
                                        seek_count++;
                                    }
                                    RR_INFO("  -> Discarded %d records, next index >= %u",
                                            seek_count, b_fork_point);
                                    g_rr_framework->replay_index = b_fork_point;
                                } else {
                                    g_rr_framework->replay_index = 0;
                                }
                            }
                            
                            /* FIX: Keep dynamic trace enabled in child process */
                            // g_rr_framework->fork_server_active = false;  // Keep as true
                            g_rr_framework->child_pid = 0;
                            
                            /* CRITICAL FIX: Directly set global variable to enable dynamic trace */
#ifdef RR_ENABLE_DYNAMIC_TRACE
                            // extern int g_dynamic_trace_pipe_fd;
                            // extern bool g_dynamic_trace_enabled;
                            
                            RR_INFO("🔍 Child %d: pipe_fd=%d, enabled_before=%d", 
                                    variant_idx, g_dynamic_trace_pipe_fd, g_dynamic_trace_enabled);
                            
                            if (g_dynamic_trace_pipe_fd >= 0) {
                                g_dynamic_trace_enabled = true;  // 直接设置
                                RR_INFO("Child %d: Forced enabled=true (PID=%d, fd=%d)", 
                                        variant_idx, getpid(), g_dynamic_trace_pipe_fd);
                            } else {
                                RR_WARN("❌ Child %d: Invalid pipe_fd=%d, cannot enable trace", 
                                        variant_idx, g_dynamic_trace_pipe_fd);
                            }
#endif
                            
                            /* 🔥 PERFORMANCE FIX: Silence child output to avoid pipe/terminal contention */
                            if (g_rr_debug.level < RR_DEBUG_INFO) {
                                int devnull = open("/dev/null", O_WRONLY);
                                if (devnull >= 0) {
                                    dup2(devnull, STDOUT_FILENO);
                                    dup2(devnull, STDERR_FILENO);
                                    close(devnull);
                                }
                            }

                            RR_INFO("Child variant %d ready (PID=%d)", variant_idx, getpid());

                            /* Install crash handlers (consistent with 'C' command) */
                            if (g_rr_framework->shared_memory) {
                                FuzzSharedMemory *crash_shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                                rr_child_install_crash_handlers(&crash_shm->variants[variant_idx]);
                            }

                            /* Reset fatal signal handlers so QEMU handles crashes, not guest handlers */
                            for (int sig = 1; sig <= TARGET_NSIG; sig++) {
                                if (sig == TARGET_SIGSEGV || sig == TARGET_SIGABRT ||
                                    sig == TARGET_SIGBUS  || sig == TARGET_SIGILL) {
                                    struct target_sigaction sa_reset;
                                    memset(&sa_reset, 0, sizeof(sa_reset));
                                    sa_reset._sa_handler = TARGET_SIG_DFL;
                                    do_sigaction(sig, &sa_reset, NULL, 0);
                                }
                            }

                            /* Flush TB cache so child generates coverage-instrumented TBs */
                            if (current_cpu) {
                                queue_tb_flush(current_cpu);
                                RR_INFO("Child variant %d: Queued TB flush for coverage instrumentation", variant_idx);
                            }

                            /* Install SIGALRM handler to ensure child exits after timeout.
                             * Persistent server targets (e.g. www) never exit voluntarily;
                             * alarm() guarantees the variant terminates so the parent can
                             * collect coverage and move on.  SIGALRM is treated as normal
                             * exit by rr_classify_wait_status (not a crash signal).
                             * QEMU blocks SIGALRM via pthread_sigmask (signalfd pattern),
                             * so unblock it explicitly before arming. */
                            {
                                const unsigned int CHILD_TIMEOUT_SECS = 10;
                                struct sigaction sa_alrm;
                                memset(&sa_alrm, 0, sizeof(sa_alrm));
                                sa_alrm.sa_handler = SIG_DFL;
                                sigaction(SIGALRM, &sa_alrm, NULL);
                                sigset_t unblock;
                                sigemptyset(&unblock);
                                sigaddset(&unblock, SIGALRM);
                                sigprocmask(SIG_UNBLOCK, &unblock, NULL);
                                alarm(CHILD_TIMEOUT_SECS);
                                RR_INFO("Child variant %d: set SIGALRM timeout=%us (unblocked)", variant_idx, CHILD_TIMEOUT_SECS);
                            }

                            return 1;  // Continue execution

                        } else if (pid > 0) {
                            /* Parent Process */
                            child_pids[variant_idx] = pid;
                            
                            /* Send fork event to tree visualizer */
                            rr_dynamic_trace_fork(getpid(), pid, g_rr_framework->replay_index);
                            
                            RR_INFO("  Forked variant %d: PID=%d", variant_idx, pid);
                            
                        } else {
                            /* Fork failed */
                            RR_ERROR("fork() failed for variant %d: %s", variant_idx, strerror(errno));
                            rr_ipc_send_status(-1);
                            break;
                        }
                    }
                    
                    /* Parent Process: Wait for all children to complete */
                    RR_INFO("Parent: Waiting for %d children...", num_variants);
                    
                    for (int i = 0; i < num_variants; i++) {
                        int status;
                        waitpid(child_pids[i], &status, 0);
                        
                        /* Analyze exit status */
                        int result_status = STATUS_NORMAL_EXIT;
                        int exit_code = 0;
                        int sig = 0;

                        rr_classify_wait_status(status, &result_status, &exit_code, &sig);
                        if (result_status == STATUS_CRASH) {
                            RR_INFO("Crash: Child variant %d exit_code=%d signal=%d", i, exit_code, sig);
                        }
                        
                        /* Send status (one for each child) */
                        if (result_status == STATUS_CRASH) {
                            rr_ipc_send_crash_status(result_status, exit_code, sig);
                        } else {
                            rr_ipc_send_status(result_status);
                        }
                    }
                    
                    RR_INFO("Batch fork completed");
                    g_rr_framework->child_pid = 0;
                }
                break;

            case 'F': // Fork command
                {
                    /* Read iteration_id from shared memory */
                    if (g_rr_framework->shared_memory) {
                        FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                        g_rr_framework->current_iteration_id = shm->iteration_id;
                        RR_VERBOSE("Case 'F': iteration_id=%u from shared memory", shm->iteration_id);
                    }
                    
                    /* Reset coverage BEFORE forking: child writes fresh data; Python reads it
                     * after rr_ipc_send_status() returns with no risk of being wiped. */
                    rr_coverage_reset();

                    /* ===== CRITICAL FIX: Load Fuzz instructions from shared memory BEFORE fork ===== */
                    if (g_rr_framework->shared_memory) {
                        RR_VERBOSE("Loading fuzz instructions from shared memory before fork");
                        
                        // Read and validate Fuzz instructions from shared memory
                        int load_result = rr_fuzz_load_from_shared_memory(g_rr_framework->shared_memory, 0);
                        if (load_result < 0) {
                            RR_ERROR("Failed to load fuzz instructions from shared memory");
                            rr_ipc_send_status(-1); // Send error status
                            break; // Do not execute fork
                        }
                        
                        RR_VERBOSE("Fuzz instructions loaded successfully, proceeding to fork");
                    } else {
                        // No shared memory, normal replay mode (no mutations)
                        RR_VERBOSE("No shared memory configured, running without mutations");
                    }
                    
                    /* Execute fork to create child process */
                    pid_t pid = fork();
                    
                    if (pid == 0) {
                        /* Child Process: Close inherited IPC FDs to avoid interference */
                        rr_child_close_ipc_fds();
                        
                        /* 🔥 CRITICAL FIX: Rewind stdin to ensure child reads input from start */
                        rr_child_rewind_stdin();
                        
                        /* 🔥 CRITICAL FIX: Child process re-opens trace file to ensure independent offset */
                        RR_INFO("Child: Re-opening trace file for independent offset");
                        fprintf(stderr, "[DEBUG-CHILD] Child PID=%d re-opening trace. Path=%s\n", 
                                getpid(), g_rr_trace_path ? g_rr_trace_path : "NULL");
                        fflush(stderr);

                        if (g_rr_trace_path) {
                            if (rr_child_start_replay_from_path(g_rr_trace_path, false, 0, "Child") < 0) {
                                fprintf(stderr, "[DEBUG-CHILD] rr_start_replay failed!\n");
                            } else {
                                fprintf(stderr, "[DEBUG-CHILD] rr_start_replay success.\n");
                            }
                        } else {
                            RR_ERROR("Child: No trace path available to re-open!");
                            fprintf(stderr, "[DEBUG-CHILD] g_rr_trace_path is NULL!\n");
                            rr_reset_trace_position();
                        }
                        fflush(stderr);
                        
                        /* Reset replay_index to 0 */
                        RR_INFO("Child: Resetting replay_index to 0");
                        g_rr_framework->replay_index = 0;
                        
                        /* Clear current record */
                        if (g_current_record) {
                            RR_INFO("Child: Disposing current record");
                            rr_record_dispose(g_current_record);
                            g_current_record = NULL;
                        }
                        
                        /* 🔥 CRITICAL FIX: Child process reloads Fuzz instructions */
                        if (g_rr_framework->shared_memory) {
                            FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                            rr_child_install_crash_handlers(&shm->variants[0]);
                            rr_child_reload_variant_instructions(0);
                            fflush(stderr);
                        }
                        
                        /* Continue Fuzzing execution */
                        g_rr_framework->child_pid = 0;
                        /* FIX: Keep trace pipe enabled */
                        // g_rr_framework->fork_server_active = false;  // Keep as true
                        
#ifdef RR_ENABLE_DYNAMIC_TRACE
                        // extern int g_dynamic_trace_pipe_fd;
                        // extern bool g_dynamic_trace_enabled;
                        if (g_dynamic_trace_pipe_fd >= 0) {
                            g_dynamic_trace_enabled = true;
                            RR_INFO("Child (F cmd): Forced trace enabled (PID=%d, fd=%d)", 
                                    getpid(), g_dynamic_trace_pipe_fd);
                            
                            /* Send iteration message (use current_iteration_id, or 0 if not set) */
                            uint32_t iter_id = g_rr_framework->current_iteration_id;
                            rr_dynamic_trace_iteration(iter_id, getpid());
                            RR_INFO("Child (F cmd): Sent iteration %u message", iter_id);
                        }
#endif
                        
                        RR_INFO("Child process started for fuzzing execution (PID=%d)", getpid());
                        RR_INFO("Child will execute syscalls from BEGINNING (early fork mode)");
                        
                        // DEBUG: Check again before return
                        fprintf(stderr, "[DEBUG-CHILD-BEFORE-RETURN] PID=%d, before returning:\n", getpid());
                        fprintf(stderr, "[DEBUG-CHILD-BEFORE-RETURN]   g_instruction_count=%zu\n", g_instruction_count);
                        fflush(stderr);
                        
                        /* FIX: Return 1 to give control back to rr_do_syscall
                         * 
                         * IMPORTANT: Since we fork before the first syscall (early fork),
                         *      the child process will continue to execute the first syscall,
                         *      then the second, third... until all syscalls.
                         *      
                         * Mutations are automatically applied during each syscall execution (apply_mutations_for_syscall).
                         * Coverage is automatically collected (shared memory bitmap).
                         */
                        RR_INFO("Child: Returning to execute syscalls with mutations (PID=%d)", getpid());

                        /* Reset fatal signal handlers (consistent with 'C' command) */
                        for (int sig = 1; sig <= TARGET_NSIG; sig++) {
                            if (sig == TARGET_SIGSEGV || sig == TARGET_SIGABRT ||
                                sig == TARGET_SIGBUS  || sig == TARGET_SIGILL) {
                                struct target_sigaction sa_reset;
                                memset(&sa_reset, 0, sizeof(sa_reset));
                                sa_reset._sa_handler = TARGET_SIG_DFL;
                                do_sigaction(sig, &sa_reset, NULL, 0);
                            }
                        }

                        /* Flush TB cache for coverage-instrumented re-translation */
                        if (current_cpu) {
                            queue_tb_flush(current_cpu);
                            RR_INFO("Child (F cmd): Queued TB flush for coverage instrumentation (PID=%d)", getpid());
                        }

                        return 1; // Return 1 indicating child should continue execution
                        
                    } else if (pid > 0) {
                        /* Parent Process: Wait for child to complete */
                        g_rr_framework->child_pid = pid;
                        
                        /* Dynamic trace: Record fork event */
                        rr_dynamic_trace_fork(getpid(), pid, 0);  // FIX: Enable fork tracing
                        
                        RR_VERBOSE("Parent process waiting for child PID=%d", pid);
                        
                        int status;
                        
                        /* Add timeout mechanism to prevent indefinite waiting */
                        int wait_result = waitpid(pid, &status, WNOHANG);
                        if (wait_result == 0) {
                            // Child still running, wait for a while
                            RR_VERBOSE("Child still running, waiting with timeout...");
                            
                            int timeout_count = 0;
                            while (wait_result == 0 && timeout_count < 5000) { // 5-second timeout
                                usleep(1000); // 1ms (Reduced from 100ms)
                                wait_result = waitpid(pid, &status, WNOHANG);
                                timeout_count++;
                            }
                            
                            if (wait_result == 0) {
                                RR_WARN("Child process timeout, forcibly terminating PID=%d", pid);
                                kill(pid, SIGKILL);
                                waitpid(pid, &status, 0); // Cleanup
                                rr_ipc_send_status(6); // STATUS_TIMEOUT (6) instead of Normal Exit (3)
                                g_rr_framework->child_pid = 0;
                                // Continue normal flow; let Python proceed to next iteration
                            }
                        }
                        
                        /* FIX: Analyze execution results and send to Conductor 
                         * 
                         * In persistent mode, the parent needs to tell the Conductor:
                         * 1. Child execution result (crash or normal).
                         * 2. Parent is still alive and ready for the next iteration.
                         * 
                         * CRITICAL: Send STATUS_AT_FORK_POINT (2) instead of STATUS_NORMAL_EXIT (3).
                         *      This allows the Conductor to know NOT to wait for the QEMU process to exit.
                         */
                        if (WIFEXITED(status)) {
                            int exit_code = WEXITSTATUS(status);
                            RR_VERBOSE("Child exited normally with code %d", exit_code);
                            
                            // ✅ CRITICAL FIX: Detect QEMU exit code (128 + signal)
                            // In some cases, QEMU catches signals and exits with 128+sig.
                            if (exit_code == 134 || exit_code == 139 || exit_code == 135 || exit_code == 132) {
                                int sig = exit_code - 128;
                                RR_INFO("Crash Found: Child exited with crash-like code %d (Signal %d)", exit_code, sig);
                                rr_ipc_send_status(4); // STATUS_CRASH
                            } else {
                                // Send AT_FORK_POINT indicating parent is ready, instead of NORMAL_EXIT
                                rr_ipc_send_status(2); // 2 = AT_FORK_POINT
                            }
                            
                        } else if (WIFSIGNALED(status)) {
                            int sig = WTERMSIG(status);
                            
                            // Check for crash signals
                            if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS || 
                                sig == SIGILL || sig == SIGFPE) {
                                RR_INFO("Crash: CRASH DETECTED: Child crashed with signal %d (%s)", 
                                       sig, strsignal(sig));
                                rr_ipc_send_status(4); // 4 = Crash Found (Conductor needs to know)
                                // Note: After crash, Conductor may choose to terminate or continue
                            } else {
                                RR_VERBOSE("Child terminated by signal %d", sig);
                                rr_ipc_send_status(5); // 5 = Other Signal
                            }
                        } else {
                            RR_WARN("Child terminated with unknown status");
                            rr_ipc_send_status(2); // Still ready for next round
                        }
                        
                        g_rr_framework->child_pid = 0;

                        /* Reset fork point state for next iteration */
                        g_at_fork_point = false;
                        RR_VERBOSE("Reset fork point for next iteration");
                        RR_VERBOSE("Completed execution (child process finished)");

                    } else {
                        /* Fork failed */
                        RR_ERROR("fork() failed: %s", strerror(errno));
                        rr_ipc_send_status(-1); // Error
                    }
                }
                break;

            // NEW: Baseline execution command (full execution without fork)
            case 'E': // Baseline execution - Full trace replay without fork
                {
                    RR_INFO("Baseline execution command received");
                    
                    if (!g_rr_framework->shared_memory) {
                        RR_ERROR("No shared memory for baseline execution");
                        rr_ipc_send_status(-1);
                        break;
                    }
                    
                    FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                    uint32_t iteration_id = shm->iteration_id;
                    
                    RR_INFO("Baseline execution: iteration=%u", iteration_id);
                    
                    // Send ITERATION message from parent
                    // extern bool g_dynamic_trace_enabled;
                    // extern int g_dynamic_trace_pipe_fd;
                    if (g_dynamic_trace_enabled && g_dynamic_trace_pipe_fd >= 0) {
                        rr_dynamic_trace_iteration(iteration_id, getpid());
                        RR_INFO("Sent ITERATION message");
                    }
                    
                    /* Reset coverage BEFORE forking so Python reads this execution's data. */
                    rr_coverage_reset();

                    // Fork a child to execute the full baseline trace
                    rr_reset_trace_position();

                    pid_t baseline_pid = fork();
                    if (baseline_pid < 0) {
                        RR_ERROR("Fork failed for baseline execution");
                        rr_ipc_send_status(-1);
                        break;
                    }
                    
                    if (baseline_pid == 0) {
                        // Child: Execute baseline trace (only up to first IO syscall)
                        g_rr_framework->silent_replay_mode = false;
                        g_rr_framework->current_iteration_id = iteration_id;
                        g_rr_framework->baseline_mode = true;

                        // 🔥 CRITICAL FIX: Set to REPLAY mode to use trace data correctly
                        g_rr_framework->mode = RR_MODE_REPLAY;
                        g_rr_framework->replay_index = 0;  // Start replay from beginning
                        RR_INFO("✅ Baseline child: Switched to REPLAY mode for proper trace execution");

                        /* 🔥 CRITICAL FIX: Flush TB cache for baseline child too */
                        if (current_cpu) {
                            queue_tb_flush(current_cpu);
                            RR_INFO("✅ Baseline child: Queued TB flush to enable coverage instrumentation");
                        }

                        // 🔥 Ensure replay system is correctly initialized (using absolute path)
                        if (g_rr_config.trace_file) {
                            // 🔥 Construct absolute path to ensure child process can find the file
                            char abs_trace_path[1024];
                            if (g_rr_config.trace_file[0] == '/') {
                                // Already absolute path
                                strncpy(abs_trace_path, g_rr_config.trace_file, sizeof(abs_trace_path) - 1);
                                abs_trace_path[sizeof(abs_trace_path) - 1] = '\0';
                            } else {
                                // Relative path, build absolute path
                                if (!getcwd(abs_trace_path, sizeof(abs_trace_path))) {
                                    RR_ERROR("Baseline child: Failed to get current working directory");
                                    _exit(1);
                                }
                                size_t len = strlen(abs_trace_path);
                                snprintf(abs_trace_path + len, sizeof(abs_trace_path) - len, "/%s", g_rr_config.trace_file);
                            }

                            // 🔥 Reset replay state and initialize
                            // extern void rr_reset_trace_position(void);
                            rr_reset_trace_position();

                            // extern int rr_start_replay(const char *trace_file);
                            if (rr_start_replay(abs_trace_path) < 0) {
                                RR_ERROR("Baseline child: Failed to initialize replay system with path: %s", abs_trace_path);
                                _exit(1);
                            }
                            RR_INFO("✅ Baseline child: Replay system initialized successfully with: %s", abs_trace_path);
                        } else {
                            RR_ERROR("Baseline child: No trace file specified");
                            _exit(1);
                        }

                        // Re-enable dynamic trace in child
                        if (g_dynamic_trace_enabled && g_dynamic_trace_pipe_fd >= 0) {
                            rr_dynamic_trace_iteration(iteration_id, getpid());
                            RR_INFO("Child sent ITERATION message");
                        }

                        RR_INFO("Baseline child: will exit at first IO syscall (fork point)");
                        return 1;
                    }
                    
                    // Parent: Wait for baseline child to complete
                    int status;
                    pid_t wait_result = waitpid(baseline_pid, &status, 0);
                    
                    if (wait_result < 0) {
                        RR_ERROR("waitpid failed for baseline child");
                        rr_ipc_send_status(-1);
                    } else {
                        RR_INFO("Baseline execution completed");
                        rr_ipc_send_status(0);
                    }
                }
                break;

            // New: Checkpoint fork command (mid-point dynamic fork)
            case 'C': // Checkpoint fork command - Mid-Point Fork
                {
                    RR_INFO("Mid-Point Fork command received");
                    
                    if (!g_rr_framework->shared_memory) {
                        RR_ERROR("No shared memory for checkpoint fork");
                        rr_ipc_send_status(-1);
                        break;
                    }
                    
                    FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                    uint32_t fork_point = shm->fork_point;
                    uint32_t depth = shm->current_depth;  // Read depth
                    uint32_t iteration_id = shm->iteration_id;  // Read iteration_id
                    int num_variants = shm->num_variants;
                    if (num_variants <= 0) num_variants = 1;
                    /* 🔥 HARDENING: Explicitly check against RR_MAX_VARIANTS to avoid OOB */
                    if (num_variants > RR_MAX_VARIANTS) {
                        RR_ERROR("Too many variants requested: %d (max %d)", num_variants, RR_MAX_VARIANTS);
                        num_variants = RR_MAX_VARIANTS;
                    }
                    
                    RR_INFO("Info: Fork command: fork_point=%u, variants=%d, depth=%u, iteration=%u",
                            fork_point, num_variants, depth, iteration_id);

                    /* TRUE MID-POINT FORK STRATEGY:
                     * 
                     * Architectural Changes:
                     * 1. Parent state reached (e.g., syscall[N]).
                     * 2. If current replay_index < fork_point:
                     *    - Set target; parent returns to main loop to continue replay.
                     *    - Fork handled on next entry to fork_server_loop when fork_point is reached.
                     * 3. If current replay_index >= fork_point:
                     *    - Fork immediately; children inherit complete parent state.
                     * 4. Children resume from the current point; no replay from start needed.
                     */
                    
                    uint32_t current_index = g_rr_framework->replay_index;
                    RR_INFO("📍 Current replay_index=%u, target fork_point=%u", current_index, fork_point);
                    
                    if (current_index < fork_point) {
                        /* Parent hasn't reached fork_point yet.
                         * We need to return control to the main loop to execute syscalls
                         * until we reach the target index.
                         */
                        RR_INFO("Parent at index %u, target %u - Returning to ADVANCE", 
                                current_index, fork_point);
                        
                        g_rr_framework->checkpoint_target = fork_point;
                        g_rr_framework->silent_replay_mode = true;
                        
                        /* FIX: Set resume flag so we auto-execute 'C' logic when we re-enter loop at fork_point */
                        g_rr_framework->resume_from_checkpoint = true;
                        
                        /* Return special code 2 to signal "Advance state" */
                        return 2;
                    } else {
                        /* Parent already at or past fork_point, fork immediately! */
                        RR_INFO("Parent already at fork_point %u, verifying consistency...", fork_point);
                        
                        /* If parent has already passed fork_point, we cannot replay backwards.
                         * Signal Python to restart QEMU with a fresh replay from the start. */
                        if (current_index > fork_point) {
                            RR_WARN("Parent overshot fork_point (current=%u > target=%u). "
                                    "Sending NEED_RESTART to Python.", current_index, fork_point);
                            /* Send one NEED_RESTART per expected variant so Python drains correctly */
                            for (int _i = 0; _i < num_variants; _i++) {
                                rr_ipc_send_status(STATUS_NEED_RESTART);
                            }
                            break;
                        }
                    }
                    
                    // Concurrent fork of all variants - dynamic multi-level fork support
                    pid_t child_pids[RR_MAX_VARIANTS];
                    memset(child_pids, 0, sizeof(child_pids));
                    int status;
                    
                    /* Reset coverage BEFORE forking: all children write fresh data into a clean
                     * bitmap; Python reads the union after the last rr_ipc_send_status(). */
                    rr_coverage_reset();

                    /* Check parent strace replay state */
                    bool parent_strace_enabled = rr_strace_replay_enabled();
                    RR_INFO("🔍 DEBUG: Parent strace_replay_enabled=%d before fork", parent_strace_enabled);

                    for (int variant_idx = 0; variant_idx < num_variants; variant_idx++) {
                        FuzzVariant *variant = &shm->variants[variant_idx];
                        size_t count = variant->instruction_count;
                        if (count > RR_FUZZ_MAX_INSTRUCTIONS) count = RR_FUZZ_MAX_INSTRUCTIONS;
                        g_instruction_count = count;
                        
                        memcpy(g_fuzz_instructions, variant->instructions,
                               sizeof(FuzzInstruction) * g_instruction_count);
                        
                        pid_t pid = fork();
                        
                        if (pid == 0) {
                            /* ═══ Child Process ═══ */
                            
                            
                            RR_VERBOSE("Child started PID=%d mode=%d", getpid(), g_rr_config.mode);
                            rr_child_close_ipc_fds();
                            
                            /* Each child reopens trace file for full isolation */
                            if (g_trace_file != NULL && g_rr_trace_path) {
                                if (rr_child_start_replay_from_path(g_rr_trace_path, true, variant_idx,
                                                                    "Checkpoint child") < 0) {
                                    _exit(1);
                                }
                            }
                            
                            /* Strace replay needs to re-initialize trace parser */
                            if (rr_strace_replay_enabled()) {
                                /* Re-initialize strace replay parser to get independent FILE* */
                                // extern int rr_strace_replay_cleanup(void);
                                // extern int rr_strace_replay_init(const char *trace_file);
                                
                                const char *trace_file = g_rr_config.trace_file;
                                if (trace_file) {
                                    RR_INFO("Child %d: Re-initializing strace replay parser with %s", variant_idx, trace_file);
                                    rr_strace_replay_cleanup();
                                    
                                    if (rr_strace_replay_init(trace_file) < 0) {
                                        RR_ERROR("Child %d: Failed to reinitialize strace replay", variant_idx);
                                        _exit(1);
                                    }
                                    RR_INFO("Child %d: Strace replay reinitialized with independent parser", variant_idx);
                                } else {
                                    RR_ERROR("Child %d: trace_file is NULL, cannot reinitialize", variant_idx);
                                }
                            }

                             /* 🔥 CRITICAL FIX: Reset fatal signal handlers in child */
                             /* We want QEMU to handle crashes, not the guest's own handlers which might hang. */
                             for (int sig = 1; sig <= TARGET_NSIG; sig++) {
                                 if (sig == TARGET_SIGSEGV || sig == TARGET_SIGABRT || 
                                     sig == TARGET_SIGBUS || sig == TARGET_SIGILL) {
                                     struct target_sigaction sa_reset;
                                     memset(&sa_reset, 0, sizeof(sa_reset));
                                     sa_reset._sa_handler = TARGET_SIG_DFL;
                                     do_sigaction(sig, &sa_reset, NULL, 0);
                                 }
                             }


                            /* Reload Fuzz instructions for child process (Checkpoint fork) */
                            rr_child_reload_variant_instructions(variant_idx);
                            fflush(stderr);

                            /* True mid-point fork implementation: Sync File Pointer */
                            if (fork_point > 0) {
                                RR_INFO("Info: Child %d: Syncing trace file to fork_point %u", variant_idx, fork_point);
                                
                                /* File is at beginning (reopened). CPU is at fork_point. */
                                /* We must fast-forward the FILE POINTER to match CPU state */
                                
                                syscall_record_t *tmp_rec = NULL;
                                int seek_count = 0;

                                /* Advance trace file until the next unread record has index >= fork_point.
                                 * We must advance by record INDEX (not by count), because trace records
                                 * have explicit index fields and may be non-contiguous (gaps exist when
                                 * syscalls are executed but not saved to the trace). */
                                while (1) {
                                    tmp_rec = read_next_record();

                                    if (!tmp_rec) {
                                        RR_ERROR("Child %d: Failed to sync trace - EOF before reaching fork_point %u (skipped %d records)",
                                                 variant_idx, fork_point, seek_count);
                                        break;
                                    }

                                    if (tmp_rec->index >= fork_point) {
                                        /* This record belongs at or after the fork point: keep it */
                                        g_current_record = tmp_rec;
                                        RR_INFO("Child %d: Kept record index=%u (>= fork_point=%u) as first record",
                                                variant_idx, tmp_rec->index, fork_point);
                                        break;
                                    }

                                    rr_record_dispose(tmp_rec);
                                    seek_count++;
                                }

                                RR_INFO("  → Synced file pointer by discarding %d records (next record index >= %u)", seek_count, fork_point);

                                /* FORCE reset replay_index to match fork_point */
                                /* rr_start_replay() likely resets it to 0, which mismatches CPU state */
                                g_rr_framework->replay_index = fork_point;
                                RR_INFO("  → Forced replay_index to %u (g_current_record reset to NULL)", g_rr_framework->replay_index);
                                fflush(stderr);
                                
                                g_rr_framework->silent_replay_mode = false;
                                g_rr_framework->checkpoint_target = 0; 
                                
                            } else {
                                // fork_point=0: Start from beginning
                                RR_INFO("Child %d: Starting from beginning (fork_point=0)", variant_idx);
                                g_rr_framework->replay_index = 0;
                                if (g_current_record) {
                                    rr_record_dispose(g_current_record);
                                    g_current_record = NULL;
                                }
                                g_rr_framework->silent_replay_mode = false;
                            }
                            
                            /* Update child process state */
                            g_rr_framework->current_depth = depth + 1;
                            // First layer children (depth+1=1) can also nested fork
                            g_rr_framework->is_autonomous_child = true;  // Children are autonomous
                            g_rr_framework->current_iteration_id = iteration_id;
 
                            
                            // Set to FUZZING mode for proper mutation application
                            g_rr_framework->mode = RR_MODE_FUZZING;
                            RR_INFO("✅ Child %d: Switched to FUZZING mode for mutation application", variant_idx);

                            rr_child_install_crash_handlers(&shm->variants[variant_idx]);

                            /* 🔥 PERFORMANCE FIX: Silence child output to avoid pipe/terminal contention */
                            if (g_rr_debug.level < RR_DEBUG_INFO) {
                                int devnull = open("/dev/null", O_WRONLY);
                                if (devnull >= 0) {
                                    dup2(devnull, STDOUT_FILENO);
                                    dup2(devnull, STDERR_FILENO);
                                    close(devnull);
                                }
                            }
                            
                            
                            /* 🔥 CRITICAL FIX: Flush TB cache to force re-translation with coverage instrumentation.
                             * The parent process may have generated TBs without coverage (or with different settings).
                             * By flushing, we ensure the child generates new TBs that include calls to
                             * rr_coverage_trace_edge, capturing execution of target code (e.g., main).
                             */
                            if (current_cpu) {
                                queue_tb_flush(current_cpu);
                                RR_INFO("✅ Child %d: Queued TB flush to enable coverage instrumentation", variant_idx);
                            } else {
                                RR_WARN("⚠️ Child %d: current_cpu is NULL, cannot flush TB cache!", variant_idx);
                            }
                            
                            /* TRUE MID-POINT FORK: Child inherits complete parent state */
                            /* 
                             * note: fork() copies:
                             * - replay_index (inherited from parent fork_point)
                             * - g_trace_file (file descriptors copied)
                             * - g_current_record (memory state)
                             * - CPU/Memory state (COW mechanism)
                             * 
                             * Child continues from fork_point; no need to replay previous syscalls.
                             */
                            
                            
                            /* Child continues from fork_point */
                            RR_INFO("TRUE Mid-Point Fork: Child %d starting from replay_index=%d (fork_point=%u)", 
                                    variant_idx, g_rr_framework->replay_index, fork_point);
                            
                            g_rr_framework->child_pid = 0;

                            /* 🔥 CRITICAL FIX: Disable checkpoint logic for children */
                            /* Children must NEVER re-enter the checkpointing loop */
                            g_rr_framework->checkpoint_target = 0;
                            g_rr_framework->fork_server_active = false;
                            g_rr_framework->resume_from_checkpoint = false;

                            
#ifdef RR_ENABLE_DYNAMIC_TRACE
                            // extern int g_dynamic_trace_pipe_fd;
                            // extern bool g_dynamic_trace_enabled;
                            if (g_dynamic_trace_pipe_fd >= 0) {
                                g_dynamic_trace_enabled = true;
                                RR_INFO("Child %d: Dynamic trace enabled (PID=%d, continuing from index %d)", 
                                        variant_idx, getpid(), g_rr_framework->replay_index);
                                
                                /* Send iteration message (do not send fork message, as it is sent by parent) */
                                rr_dynamic_trace_iteration(iteration_id, getpid());
                            }
#endif
                            
                            /* Child continues execution, processing subsequent syscalls starting from the current replay_index */
                            RR_INFO("🔍 DEBUG: About to return 1, silent_replay_mode=%d, checkpoint_target=%u",
                                    g_rr_framework->silent_replay_mode, g_rr_framework->checkpoint_target);
                            
                            /* Check if strace replay is enabled */
                            // extern bool rr_strace_replay_enabled(void);
                            bool strace_enabled = rr_strace_replay_enabled();
                            RR_INFO("🔍 DEBUG: Child %d strace_replay_enabled=%d", variant_idx, strace_enabled);

                            /* Variant timeout: persistent server targets never exit voluntarily.
                             * After mutations diverge from the trace, native select/poll would
                             * block forever.  SIGALRM with SIG_DFL terminates the child.
                             * QEMU blocks SIGALRM in the main thread (signalfd pattern), so we
                             * must unblock it here before arming alarm(). */
                            {
                                const unsigned int CHILD_TIMEOUT_SECS = 10;
                                struct sigaction sa_alrm;
                                memset(&sa_alrm, 0, sizeof(sa_alrm));
                                sa_alrm.sa_handler = SIG_DFL;
                                sigaction(SIGALRM, &sa_alrm, NULL);
                                sigset_t unblock;
                                sigemptyset(&unblock);
                                sigaddset(&unblock, SIGALRM);
                                sigprocmask(SIG_UNBLOCK, &unblock, NULL);
                                alarm(CHILD_TIMEOUT_SECS);
                            }

                            return 1;
                            
                        } else if (pid > 0) {
                            /* Parent: Record child PID, continue forking other children (Concurrent) */
                            child_pids[variant_idx] = pid;
                            rr_dynamic_trace_fork(getpid(), pid, fork_point);
                            RR_INFO("  Forked variant %d: PID=%d (Concurrent, no wait)", variant_idx, pid);
                            // Do not wait; let children execute concurrently
                        } else {
                            RR_ERROR("Fork failed for variant %d", variant_idx);
                            break;
                        }
                    }
                    
                    // Wait for all children to complete
                    RR_INFO("⏳ Waiting for %d children to complete...", num_variants);
                    for (int i = 0; i < num_variants && i < 10; i++) {
                        if (child_pids[i] > 0) {
                            waitpid(child_pids[i], &status, 0);
                            
                            // Analyze child exit status and extract detailed information
                            int result_status = STATUS_NORMAL_EXIT;
                            int exit_code = 0;
                            int signal_number = 0;
                            
                            rr_classify_wait_status(status, &result_status, &exit_code, &signal_number);
                            if (result_status == STATUS_CRASH) {
                                RR_INFO("Crash: Child %d exit_code=%d signal=%d", i, exit_code, signal_number);
                            }
                            
                            // Send crash status including exit_code and signal
                            if (result_status == STATUS_CRASH) {
                                rr_ipc_send_crash_status(result_status, exit_code, signal_number);
                            } else {
                                rr_ipc_send_status(result_status);
                            }
                            
                            RR_INFO("  Child %d (PID=%d) finished: status=%d", i, child_pids[i], result_status);
                        }
                    }
                    
                    RR_INFO("Fork completed: %d variants", num_variants);
                    g_rr_framework->child_pid = 0;
                }
                break;

            case 'T': // Tree export command — dump syscall tree to JSON for PathFinder
                {
                    char tree_path[256];
                    snprintf(tree_path, sizeof(tree_path),
                             "/tmp/syscall_tree_%d.json", getpid());
                    rr_tree_export_json(tree_path);
                    RR_INFO("Syscall tree exported to %s", tree_path);
                    rr_ipc_send_status(8); // 8 = tree exported
                }
                break;

            case 'Q': // Quit command
                RR_LOG("Fork Server received quit command");
                return -1; // Terminate execution

            case 'S': // Save Snapshot command (reserved)
                // TODO: Implement process state snapshotting
                // Requires saving: CPU registers, memory snapshot, FD mapping, etc.
                RR_WARN("Snapshot save not implemented (stub only)");
                rr_ipc_send_status(6); // 6 = Snapshot Saved
                break;

            case 'L': // Load Snapshot command (reserved)
                // TODO: Implement restoration from snapshot
                RR_WARN("Snapshot load not implemented (stub only)");
                rr_ipc_send_status(7); // 7 = Snapshot Loaded
                break;

            case 0: // No command
                usleep(1000); // Wait briefly
                break;

            default:
                RR_LOG("Unknown fork server command: %d", cmd);
                break;
        }
    }

    return 0;
}

/**
 * Auto-detect Fork Point (Enhanced with Fallback)
 * 
 * Improvements:
 * 1. Supports multiple fork strategies (strict/relaxed/aggressive/fallback).
 * 2. Fallback mechanism: Forces fork if N syscalls passed without a fork.
 * 
 * @param syscall_nr Syscall number
 * @param syscall_name Syscall name (optional)
 * @param ret Syscall return value
 * @return true if fork server loop should be entered
 */
bool rr_check_auto_fork_point(int syscall_nr, const char *syscall_name, abi_long ret)
{
    static int syscalls_since_ready = 0;  // Fallback counter
    
    if (!g_rr_framework->fork_server_active) {
        return false;
    }
    
    /* If already at fork point, send status and return */
    if (g_at_fork_point) {
        RR_IPC_TRACE("Sending At Fork Point status (already at fork point)");
        if (rr_ipc_send_status(2) < 0) {
            RR_WARN("Failed to send At Fork Point status");
        }
        return true;
    }
    
    /* Increment counter (for fallback) */
    syscalls_since_ready++;
    
    /* Build-in strategy fork detection */
    const syscall_info_t *info = rr_get_syscall_info(syscall_nr);
    bool should_fork = rr_should_auto_fork(syscall_nr, ret);
    
    RR_VERBOSE("Auto-fork check: %s (class=%s, ret=%ld, strategy=%d, should_fork=%d)",
               info->name,
               rr_get_syscall_class_name(info->class),
               (long)ret,
               g_rr_config.fork_strategy,
               should_fork);
    
    if (should_fork) {
        g_at_fork_point = true;
        RR_INFO("Auto-detected fork point: %s (class=%s, ret=%ld, strategy=%d, after %d syscalls)",
                info->name, 
                rr_get_syscall_class_name(info->class),
                (long)ret,
                g_rr_config.fork_strategy,
                syscalls_since_ready);
        
        RR_IPC_TRACE("Sending At Fork Point status (auto-detected)");
        if (rr_ipc_send_status(2) < 0) {
            RR_WARN("Failed to send At Fork Point status");
        }
        
        syscalls_since_ready = 0;  // Reset counter
        return true;
    }
    
    /* Strategy 2: Fallback mechanism - Force fork if N syscalls passed without a fork */
    if (syscalls_since_ready >= g_rr_config.fork_fallback_threshold) {
        const syscall_info_t *info_inner = rr_get_syscall_info(syscall_nr);
        
        /* Fallback only on suitable syscalls (I/O or FD related) */
        if (info_inner->class == SYSCALL_CLASS_IO || info_inner->class == SYSCALL_CLASS_FD) {
            g_at_fork_point = true;
            RR_WARN("Warning:  Fallback fork triggered: %s after %d syscalls without fork",
                    info_inner->name, syscalls_since_ready);
            
            RR_IPC_TRACE("Sending At Fork Point status (fallback)");
            if (rr_ipc_send_status(2) < 0) {
                RR_WARN("Failed to send At Fork Point status");
            }
            
            syscalls_since_ready = 0;
            return true;
        }
    }
    
    return false;
}
