/**
 * RR-Fuzz Main Module - Framework initialization and core logic
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "../../../qemu.h"
#include "../../../user-internals.h"
#include "../../../user-mmap.h"
#include "../../../syscall_defs.h"
#include "rr_framework.h"
#include "rr_bb_trace.h"
#include "rr_replay_strace.h"
#include "rr_aux_data.h"
#include "rr_dynamic_trace.h"
#include "rr_coverage.h"
#include "rr_syscall_dispatch.h"
#include "rr_syscall_tree.h"
#include "rr_mock_ioctls.h"
#include "rr_constants.h"
#include "qemu/error-report.h"
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>


/* rr_flush_tb_cache is now correctly leveraging header definitions */
void rr_flush_tb_cache(void)

{
    if (thread_cpu) {
        RR_INFO("Flushing TB cache to apply new configuration...");
        queue_tb_flush(thread_cpu);
    } else {
        RR_WARN("Cannot flush TB cache: thread_cpu is NULL");
    }
}


/* Ensure RR_DEBUG is defined */
#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif


/* Global framework state */
rr_framework_t *g_rr_framework = NULL;

/* Recursion guard for hooks */
static __thread bool g_in_rr_hook = false;

/* Temporary storage for mmap address mapping */
target_ulong g_pending_mmap_recorded_addr = 0;
target_ulong g_pending_mmap_length = 0;

/**
 * @brief Converts a syscall number to a readable name string.
 * 
 * This function provides a mapping from syscall numbers to names, primarily used for logging 
 * and debug output. For known commonly used syscalls, it returns their standard names 
 * (e.g., "read", "write"). For unidentified syscalls, it returns "unknown".
 * 
 * @param syscall_nr Syscall number (e.g., TARGET_NR_read, TARGET_NR_write)
 * @return Constant string pointer to the syscall name.
 *         - For known calls: returns the standard name string (e.g., "read", "mmap")
 *         - For unknown calls: returns "unknown"
 * 
 * @note The current implementation only includes mappings for about 30 common syscalls 
 *        and does not cover all syscalls.
 * @note The returned string pointer points to a static constant area; the caller 
 *       does not need to free the memory.
 * @warning Returns "unknown" for unmapped syscalls; callers should handle this accordingly.
 * 
 * @see rr_syscall_post_hook() primarily uses this function for log output.
 */
static const char* get_syscall_name(int syscall_nr) {
    const char *name = rr_get_syscall_name_fast(syscall_nr);
    if (name) return name;

    /* Fallback for common numbers if dispatcher not fully initialized or missing */
    switch (syscall_nr) {
#ifdef TARGET_NR_read
        case TARGET_NR_read: return "read";
#endif
#ifdef TARGET_NR_write
        case TARGET_NR_write: return "write";
#endif
#ifdef TARGET_NR_exit_group
        case TARGET_NR_exit_group: return "exit_group";
#endif
#ifdef TARGET_NR_exit
        case TARGET_NR_exit: return "exit";
#endif
        default: return "unknown";
    }
}

/**
 * @brief Determines if the deviation of a syscall return value is within the expected range.
 * 
 * During deterministic replay, the return values of certain syscalls may differ between the 
 * record and replay stages due to mechanisms such as ASLR (Address Space Layout Randomization) 
 * or PID allocation by the operating system. This function is used to judge whether such 
 * deviation is within the expected range (i.e., whether it originates from a known source 
 * of non-determinism), thereby deciding if an inconsistency warning should be triggered.
 * 
 * @param syscall_nr Syscall number (e.g., TARGET_NR_mmap, TARGET_NR_brk)
 * @param recorded The return value of the syscall during the record stage
 * @param actual The actual return value of the syscall during the replay stage
 * @return bool
 *         - true: Deviation is within the expected range (e.g., address-related or PID/TID-related syscalls)
 *         - false: Abnormal deviation, which may require further inspection or warning
 * 
 * @note Currently supported expected deviation scenarios include:
 *       - Memory management: mmap, mmap2, brk, mremap (returned addresses affected by ASLR)
 *       - Process identification: set_tid_address, gettid, getpid, getppid
 *       - Path operations: readlink, readlinkat (path length may change)
 * 
 * @warning For syscalls not listed, this function returns false, indicating no deviation is accepted.
 *          When adding new expected deviation scenarios, their rationality must be carefully evaluated.
 * 
 * @see rr_do_syscall() calls this function when a return value inconsistency is detected.
 */
static bool is_expected_deviation(int syscall_nr, abi_long recorded, abi_long actual) {
    /* mmap address deviation is expected (ASLR) */
#ifdef TARGET_NR_mmap
    if (syscall_nr == TARGET_NR_mmap) {
        return true;
    }
#endif
#ifdef TARGET_NR_mmap2
    if (syscall_nr == TARGET_NR_mmap2) {
        return true;
    }
#endif
    
    /* brk address deviation is also expected */
    if (syscall_nr == TARGET_NR_brk) {
        return true;
    }
    
    /* mremap address deviation is also expected */
#ifdef TARGET_NR_mremap
    if (syscall_nr == TARGET_NR_mremap) {
        return true;
    }
#endif
    
    /* set_tid_address returns thread ID, which differs every run */
#ifdef TARGET_NR_set_tid_address
    if (syscall_nr == TARGET_NR_set_tid_address) {
        return true;
    }
#endif
    
    /* readlink return value may change due to path length variations */
#ifdef TARGET_NR_readlink
    if (syscall_nr == TARGET_NR_readlink) {
        return true;
    }
#endif
#ifdef TARGET_NR_readlinkat
    if (syscall_nr == TARGET_NR_readlinkat) {
        return true;
    }
#endif
    
    /* gettid returns thread ID */
#ifdef TARGET_NR_gettid
    if (syscall_nr == TARGET_NR_gettid) {
        return true;
    }
#endif
    
    /* getpid/getppid may change */
    // Handle architectural differences: some architectures use different syscall names
#ifdef TARGET_NR_getpid
    if (syscall_nr == TARGET_NR_getpid) return true;
#endif
#ifdef TARGET_NR_getxpid  // alpha architecture
    if (syscall_nr == TARGET_NR_getxpid) return true;
#endif
#ifdef TARGET_NR_getppid
    if (syscall_nr == TARGET_NR_getppid) return true;
#endif
    
    return false;
}

/**
 * @brief Aligns the file descriptor (FD) environment in replay mode.
 * 
 * To ensure deterministic replay, the guest program's FD allocation during the replay 
 * stage should be as consistent as possible with the record stage. This function is called 
 * at the start of replay/fuzzing mode to attempt to close some FDs occupied by QEMU, so that 
 * the guest program's first open() call can obtain the same FD number as in the record 
 * stage (usually FD=3).
 * 
 * @return int
 *         - 0: Alignment operation completed (regardless of success)
 *         - negative value: Reserved for future error handling extensions
 * 
 * @note FD alignment strategy:
 *       1. Skip standard streams (stdin=0, stdout=1, stderr=2)
 *       2. Protect IPC communication pipe FDs (required for fuzzing mode)
 *       3. Only close FDs opened in read-only mode to avoid accidentally closing the trace file
 * 
 * @note If full alignment is not possible (e.g., QEMU occupies multiple FDs), the system 
 *       enables an FD mapping mechanism to handle discrepancies between record and replay FDs.
 * 
 * @warning Race conditions may exist in multi-threaded environments (currently QEMU user-mode is single-threaded)
 * 
 * @see rr_fd_mapping_add() implementation of the FD mapping mechanism
 * @see rr_framework_init() called during framework initialization
 */
static int align_fd_state(void) {
    if (g_rr_config.mode != RR_MODE_REPLAY && g_rr_config.mode != RR_MODE_FUZZING) {
        return 0;
    }
    
    RR_INFO("Aligning FD state for replay/fuzzing mode...");
    
    /* Get IPC FDs and ensure they are not closed */
    int ipc_cmd_fd = -1, ipc_status_fd = -1;
    const char *cmd_fd_str = getenv("RR_CMD_PIPE");
    const char *status_fd_str = getenv("RR_STATUS_PIPE");
    if (cmd_fd_str) {
        ipc_cmd_fd = atoi(cmd_fd_str);
        RR_VERBOSE("Protecting IPC command FD %d from alignment", ipc_cmd_fd);
    }
    if (status_fd_str) {
        ipc_status_fd = atoi(status_fd_str);
        RR_VERBOSE("Protecting IPC status FD %d from alignment", ipc_status_fd);
    }
    
    /* 1. Find the smallest available FD (skip standard streams 0,1,2) */
    int min_available_fd = -1;
    for (int fd = RR_FIRST_USER_FD; fd < RR_MAX_CHECKED_FD; fd++) {
        if (fcntl(fd, F_GETFD) == -1) {
            /* FD does not exist, this is the first available one */
            min_available_fd = fd;
            break;
        }
    }
    
    if (min_available_fd == -1) {
        RR_WARN("No available FD found in range %d-%d, cannot align",
                RR_FIRST_USER_FD, RR_MAX_CHECKED_FD);
        return 0; /* Do not block initialization */
    }
    
    RR_INFO("First available FD: %d", min_available_fd);
    
    /* 2. If the first available FD > 3, it means some FDs are occupied by QEMU */
    /*    Try to close non-critical FDs (but be careful to avoid closing important ones) */
    if (min_available_fd > 3) {
        int closed_count = 0;
        for (int fd = 3; fd < min_available_fd; fd++) {
            /* Try checking if an FD can be closed */
            /* NOTE: We cannot directly access g_trace_file (it resides in another module) */
            /*       So we adopt a conservative strategy: only close FDs that can be confirmed as non-critical */
            
            /* Try to get FD status */
            int flags = fcntl(fd, F_GETFL);
            if (flags == -1) {
                continue; /* FD no longer exists */
            }
            
            /* Skip IPC FD - these are required for fuzzing mode */
            if (fd == ipc_cmd_fd || fd == ipc_status_fd) {
                RR_VERBOSE("Keeping FD %d (IPC pipe)", fd);
                continue;
            }
            
            /* Conservative strategy: Only close FDs opened in read mode (safer) */
            /* Because trace files are usually in write mode */
            if ((flags & O_ACCMODE) == O_RDONLY) {
                if (close(fd) == 0) {
                    closed_count++;
                    RR_VERBOSE("Closed read-only FD %d for alignment", fd);
                }
            } else {
                RR_VERBOSE("Keeping FD %d (write/rdwr mode)", fd);
            }
        }
        
        if (closed_count > 0) {
            RR_INFO("Closed %d FDs for environment alignment", closed_count);
        } else {
            RR_WARN("Could not close any FDs - alignment may be incomplete");
        }
    }
    
    /* 3. Re-check the first available FD */
    for (int fd = RR_FIRST_USER_FD; fd < RR_MAX_CHECKED_FD; fd++) {
        if (fcntl(fd, F_GETFD) == -1) {
            RR_INFO("After alignment, first available FD: %d", fd);
            
            /* If it's still not fd=3, open dummy FDs */
            if (fd > 3) {
                RR_WARN("Cannot fully align FDs, guest's first open() will return fd=%d", fd);
                /* NOTE: This will lead to FD mapping, but at least there's a mapping mechanism to handle it now */
            }
            return 0;
        }
    }
    
    return 0;
}

 /**
 * @brief Initialize all subsystems of the RR-Fuzz framework.
 * 
 * This is the main initialization function for the RR-Fuzz framework, responsible for starting 
 * the appropriate subsystems based on the configuration (record/replay/fuzzing mode).
 * This function is typically called once before QEMU starts the guest program.
 * 
 * Initialization flow:
 * 1. Load and validate configuration (rr_config_init)
 * 2. Initialize debug logging system
 * 3. Allocate global framework context (g_rr_framework)
 * 4. Initialize FD/address mapping manager
 * 5. Execute FD environment alignment (replay/fuzzing mode)
 * 6. Initialize IPC communication pipes (fuzzing mode)
 * 7. Initialize coverage tracking module
 * 8. Initialize Syscall Tree Builder
 * 9. Start record/replay/fuzzing subsystem based on running mode
 * 
 * @return int
 *         - 0: Initialization successful
 *         - -1: Initialization failed (error log will be printed)
 * 
 * @note This function should be called only once. Repeated calls will result in resource leaks.
 * @note Automatically registers atexit cleanup function rr_framework_cleanup()
 * 
 * @warning If initialization fails, some subsystems may have already completed initialization. 
 *          The caller should ensure proper error handling and exit the program, or call 
 *          rr_framework_cleanup() to clean up.
 * 
 * @see rr_framework_cleanup() Corresponding cleanup function
 * @see g_rr_config Global configuration object
 * @see g_rr_framework Global framework context
 */
int rr_framework_init(void)
{
    const char *strace_mode_env = NULL;  // Used for detecting strace mode
    
    /* Initialize configuration system */
    if (rr_config_init() < 0) {
        error_report("RR-Fuzz: Failed to initialize configuration");
        return -1;
    }

    /* Debug: Print configuration state */
    fprintf(stderr, "[DEBUG-INIT] rr_config_init returned. enabled=%d, mode=%d\n", 
            g_rr_config.enabled, g_rr_config.mode);
    fflush(stderr);

    /* Check if enabled */
    if (!g_rr_config.enabled) {
        fprintf(stderr, "[DEBUG-INIT] Framework disabled via g_rr_config.enabled=false\n");
        return 0; // Not enabled, return directly
    }

    fprintf(stderr, "[DEBUG-INIT] Framework ENABLED! Proceeding to init debug system...\n");

    /* Initialize debug system */
    rr_debug_init();


    /* Print configuration information */
    rr_config_print();
    fprintf(stderr, "[DEBUG-INIT] config_print done\n");

    /* Allocate global context */
    g_rr_framework = g_malloc0(sizeof(rr_framework_t));
    if (!g_rr_framework) {
        RR_ERROR("Failed to allocate framework context");
        return -1;
    }
    fprintf(stderr, "[DEBUG-INIT] g_malloc done\n");

    /* Get running mode from configuration */
    g_rr_framework->mode = g_rr_config.mode;
    g_rr_framework->enabled = g_rr_config.enabled;  // Set enabled flag
    g_rr_framework->root_pid = getpid();            // ✅ Record root PID for cleanup safety

    /* Initialize mapping manager (FD/address mapping) */
    if (rr_mapping_manager_init(RR_FD_MAPPING_BUCKETS, RR_ADDR_MAPPING_BUCKETS) < 0) {
        RR_ERROR("Failed to initialize mapping manager");
        goto error;
    }
    fprintf(stderr, "[DEBUG-INIT] mapping_manager_init done\n");

    /* FD environment alignment for replay/fuzzing mode */
    if (align_fd_state() < 0) {
        RR_ERROR("Failed to align FD state");
        goto error;
    }
    fprintf(stderr, "[DEBUG-INIT] align_fd_state done\n");

    /* Register exit cleanup function */
    atexit(rr_framework_cleanup);
    RR_VERBOSE("Registered exit cleanup handler");

    /* Initialize subsystems */
    if (rr_ipc_init() < 0) {
        RR_ERROR("Failed to initialize IPC");
        goto error;
    }
    fprintf(stderr, "[DEBUG-INIT] ipc_init done\n");
    RR_INFO("IPC subsystem initialized");
    
    /* Initialize coverage tracking (Used for all execution modes) */
    RR_VERBOSE("Attempting to initialize coverage tracking...");
    fprintf(stderr, "[DEBUG-INIT] calling rr_coverage_init...\n");
    int cov_ret = rr_coverage_init(NULL);
    RR_VERBOSE("rr_coverage_init() returned: %d", cov_ret);
    if (cov_ret < 0) {
        RR_WARN("Failed to initialize coverage tracking (non-fatal), return=%d", cov_ret);
    } else {
        RR_INFO("Coverage tracking initialized successfully");
        // CRITICAL: Enable coverage in RECORD mode to capture initial trace execution
        // This is where target code actually runs! REPLAY just replays syscalls.
        if (g_rr_config.mode == RR_MODE_FUZZING || 
            g_rr_config.mode == RR_MODE_REPLAY ||
            g_rr_config.mode == RR_MODE_RECORD) {
            rr_coverage_enable();
            RR_INFO("Coverage tracking enabled for mode %d", g_rr_config.mode);
        }
    }

    rr_tree_init();
    RR_INFO("Syscall tree builder initialized");

#if defined(TARGET_MIPS)
    /* Allocate sink page for MIPS ABI compatibility (fixing 'at' register corruption) */
    if (g_rr_config.enabled) {
        g_rr_compat_sink_page = target_mmap(0, 4096, PROT_READ | PROT_WRITE,
                                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (g_rr_compat_sink_page != -1) {
            RR_INFO("MIPS Compatibility Sink Page allocated at 0x" TARGET_ABI_FMT_lx, 
                    g_rr_compat_sink_page);
        } else {
            RR_WARN("Failed to allocate MIPS compatibility sink page");
            g_rr_compat_sink_page = 0;
        }
    }
#endif

    /* Initialize BB trace if requested via environment */
    const char *bb_trace_env = getenv("RR_BB_TRACE_ENABLED");
    if (bb_trace_env && (strcmp(bb_trace_env, "1") == 0 || strcasecmp(bb_trace_env, "true") == 0)) {
        if (rr_bb_trace_init(g_rr_config.trace_file) < 0) {
            RR_WARN("Failed to initialize BB trace");
        }
    }
    
#ifdef RR_ENABLE_DYNAMIC_TRACE
    /* Initialize dynamic trace pipe (for tree visualization) */
    const char *trace_pipe_path = getenv("RR_TRACE_PIPE");
    if (trace_pipe_path) {
        /* Open in blocking mode to ensure the visualizer is ready */
        int trace_fd = open(trace_pipe_path, O_WRONLY);
        if (trace_fd >= 0) {
            rr_dynamic_trace_init(trace_fd);
            RR_INFO("Dynamic trace pipe connected: %s (FD=%d)", trace_pipe_path, trace_fd);
        } else {
            RR_WARN("Failed to open dynamic trace pipe: %s (errno=%d)", trace_pipe_path, errno);
        }
    }
#endif
    
    /* Reset Fork Server state on new process startup */
    rr_reset_fork_point();

    /* Start functionality based on mode */
    switch (g_rr_framework->mode) {
        case RR_MODE_DISABLED:
            RR_INFO("RR-Fuzz mode is disabled, no initialization required");
            break;
        case RR_MODE_RECORD:
            RR_INFO("Starting recording mode, trace_file=%s", g_rr_config.trace_file);
            if (rr_start_recording(g_rr_config.trace_file) < 0) {
                RR_ERROR("Failed to start recording");
                goto error;
            }
            RR_INFO("Recording started successfully");
            break;
        case RR_MODE_REPLAY:
            /* Check if strace replay mode is enabled */
            {
                strace_mode_env = getenv("RR_STRACE_MODE");
                RR_INFO("Starting replay mode, trace_file=%s", g_rr_config.trace_file);
                RR_INFO("RR_STRACE_MODE environment variable: %s", strace_mode_env ? strace_mode_env : "NULL");
                
                if (strace_mode_env) {
                    RR_INFO("Starting strace replay mode");
                    if (rr_strace_replay_init(g_rr_config.trace_file) < 0) {
                        RR_ERROR("Failed to start strace replay");
                        goto error;
                    }
                    RR_INFO("Strace replay started successfully");
                } else {
                    RR_INFO("Starting binary replay mode");
                    if (rr_start_replay(g_rr_config.trace_file) < 0) {
                        RR_ERROR("Failed to start binary replay");
                        goto error;
                    }
                    RR_INFO("Binary replay started successfully");
                }
            }
            break;
        case RR_MODE_FUZZING:
        case RR_MODE_REPLAY_ADVANCE:
            // Fuzzing/Advance mode needs to load trace first, then start fork server
            RR_INFO("Starting fuzzing/advance mode, trace_file=%s", g_rr_config.trace_file);
            
            // Check if strace mode is used (consistent with replay mode)
            strace_mode_env = getenv("RR_STRACE_MODE");
            if (strace_mode_env) {
                RR_INFO("Starting strace replay mode for fuzzing");
                if (rr_strace_replay_init(g_rr_config.trace_file) < 0) {
                    RR_ERROR("Failed to start strace replay for fuzzing");
                    goto error;
                }
                RR_INFO("Strace replay started successfully for fuzzing");
            } else {
                // Use native replay
                if (rr_start_replay(g_rr_config.trace_file) < 0) {
                    RR_ERROR("Failed to load trace for fuzzing");
                    goto error;
                }
            }
            /* Start Fork Server in fuzzing mode (auto-detection) */
            fprintf(stderr, "[DEBUG-INIT] Checking fork_server_enabled: %d\n", g_rr_config.fork_server_enabled);
            if (g_rr_config.fork_server_enabled) {
                RR_INFO("Starting fork server in auto-detection mode");
                fprintf(stderr, "[DEBUG-INIT] Calling rr_start_fork_server()...\n");
                       
                if (rr_start_fork_server(NULL, NULL) < 0) {
                    RR_ERROR("Failed to start fork server");
                    goto error;
                }
            }
            RR_INFO("Fuzzing mode started successfully");
            break;
        default:
            RR_ERROR("Unknown RR mode: %d", g_rr_framework->mode);
            goto error;
    }

    g_rr_framework->enabled = true;
    RR_INFO("RR-Fuzz framework initialized successfully, mode=%d (%s)",
             g_rr_framework->mode,
             g_rr_framework->mode == RR_MODE_RECORD ? "RECORD" :
             g_rr_framework->mode == RR_MODE_REPLAY ? "REPLAY" :
             g_rr_framework->mode == RR_MODE_FUZZING ? "FUZZING" :
             g_rr_framework->mode == RR_MODE_REPLAY_ADVANCE ? "REPLAY_ADVANCE" : "UNKNOWN");
    return 0;

error:
    rr_framework_cleanup();
    return -1;
}

/**
 * @brief Clean up RR-Fuzz framework and release all resources.
 * 
 * This function handles stopping all running subsystems and releasing memory
 * occupied by the framework. It is automatically called via atexit but can 
 * also be called manually.
 * 
 * Cleanup flow:
 * 1. Stop active subsystem according to mode (recording/replay/fork-server).
 * 2. Export Syscall Tree to JSON file (defaults to /tmp/syscall_tree.json).
 * 3. Clean up coverage tracking module.
 * 4. Clean up IPC communication pipes.
 * 5. Clean up dynamic trace pipes (if enabled).
 * 6. Clean up fuzzing, snapshot, debug, and config subsystems.
 * 7. Clean up FD/address mapping managers.
 * 8. Release trace record linked list.
 * 9. Free global framework context.
 * 
 * @note This function is safe to call multiple times (checks g_rr_framework == NULL).
 * @note Cleanup order is important: stop business logic first, then clean up resources.
 * 
 * @warning After calling, g_rr_framework is set to NULL; framework functions 
 *          should not be used thereafter.
 * 
 * @see rr_framework_init() Initialization function.
 * @see g_rr_framework Global framework context.
 */
void rr_framework_cleanup(void)
{
    if (!g_rr_framework) {
        return;
    }

    /* ✅ Only the root process should perform cleanup (tree export, etc.)
     * Child processes (forked) should exit silently to avoid contention 
     * on shared resources and double-exporting the tree.
     */
    if (getpid() != g_rr_framework->root_pid) {
        return;
    }

    RR_INFO("Starting RR-Fuzz framework cleanup (PID=%d)", getpid());

    /* Stop current mode */
    switch (g_rr_framework->mode) {
        case RR_MODE_DISABLED:
            // No cleanup needed
            break;
        case RR_MODE_RECORD:
            rr_stop_recording();
            break;
        case RR_MODE_REPLAY:
            if (rr_strace_replay_enabled()) {
                rr_strace_replay_cleanup();
            } else {
                rr_stop_replay();
            }
            break;
        case RR_MODE_FUZZING:
            rr_stop_fork_server();
            // Fuzzing mode also needs to stop replay; check if strace mode is used
            if (rr_strace_replay_enabled()) {
                rr_strace_replay_cleanup();
            } else {
                rr_stop_replay();
            }
            break;
        default:
            break;
    }

    /* Clean up subsystems */
    RR_VERBOSE("Cleaning up subsystems");

    /* Export Syscall Tree as HTML (Record and Fuzzing modes) */
    if (g_rr_framework->mode == RR_MODE_RECORD || 
        g_rr_framework->mode == RR_MODE_FUZZING || 
        g_rr_framework->mode == RR_MODE_REPLAY) {
        
        const char *tree_output = getenv("RR_TREE_OUTPUT");
        // Pass tree_output directly (can be NULL for default /tmp/syscall_tree_{pid}.html)
        rr_tree_export_json(tree_output);
    }
    rr_tree_cleanup();
    RR_VERBOSE("Syscall tree cleaned up");

    /* Cleanup Coverage module */
    rr_coverage_cleanup();
    RR_VERBOSE("Coverage tracking cleaned up");

    rr_ipc_cleanup();
    
#ifdef RR_ENABLE_DYNAMIC_TRACE
    /* Cleanup Dynamic Trace */
    rr_dynamic_trace_cleanup();
#endif
    
    rr_fuzz_cleanup();
    rr_snapshot_cleanup();
    rr_debug_cleanup();
    rr_config_cleanup();

    /* Cleanup mapping manager */
    rr_mapping_manager_cleanup();

    /* Cleanup trace records */
    syscall_record_t *record = g_rr_framework->trace_head;
    while (record) {
        syscall_record_t *next = record->next;
        /* Clean up argument data */
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
            if (record->arg_data[i]) {
                g_free(record->arg_data[i]);
            }
        }
        g_free(record);
        record = next;
    }

    g_free(g_rr_framework);
    g_rr_framework = NULL;
    RR_INFO("RR-Fuzz framework cleanup completed");
}

/**
 * @brief Core syscall interception and handling function of the RR-Fuzz framework.
 * 
 * This function serves as the primary entry point for the RR-Fuzz framework into QEMU.
 * It is called by `do_syscall()` in `linux-user/syscall.c` BEFORE the syscall execution.
 * Based on the current mode (record/replay/fuzzing), it decides whether to record, 
 * replay, or execute the syscall with modifications.
 * 
 * **Workflow**:
 * - **Record Mode**: Returns -1, allowing QEMU to execute the original syscall; results
 *   are recorded in the post-hook.
 * - **Replay Mode**: Calls `rr_replay_syscall()` or `rr_replay_syscall_strace()`, replaying
 *   syscall results deterministically from the trace file.
 * - **Fuzzing Mode**: Similar to replay but applies mutations and supports the fork-server mechanism.
 * 
 * **Fork-Server Mechanism**:
 * In fuzzing mode, this function enters the fork-server loop before the first syscall, 
 * ensuring that forked child processes start execution from `main()`, naturally replaying the trace.
 * 
 * @param env CPU architecture state pointer (CPUArchState).
 * @param num Syscall number.
 * @param arg1-arg8 Pointers to the 8 syscall arguments (can be modified).
 * 
 * @return abi_long
 *         - Not -1: Syscall return value handled by RR-Fuzz; QEMU uses this directly.
 *         - -1: Not handled by RR-Fuzz; let QEMU execute the original syscall (record mode or disabled).
 * 
 * @note This is a pre-hook, called BEFORE syscall execution.
 * @note In fuzzing mode, the fork-server is initialized only once (static bool fork_server_entered).
 * @note Exit-related syscalls (exit/exit_group) are handled specially in record mode.
 * 
 * @warning This function may directly modify the values pointed to by arg1-arg8 (used for mutations in fuzzing mode).
 * @warning Fork-server logic results in process forking; callers must consider multi-process scenarios.
 * 
 * @see do_syscall() QEMU entry point calling this function.
 * @see rr_syscall_post_hook() Corresponding post-hook (after syscall execution).
 * @see rr_replay_syscall() Binary trace replay implementation.
 * @see rr_replay_syscall_strace() Strace replay implementation.
 * @see rr_fork_server_loop() Fork-server loop implementation.
 */
abi_long rr_do_syscall(CPUArchState *env, int num,
                       abi_long *arg1, abi_long *arg2, abi_long *arg3, abi_long *arg4,
                       abi_long *arg5, abi_long *arg6, abi_long *arg7, abi_long *arg8)
{
    RR_VERBOSE("RR_DO_SYSCALL: Called for syscall %d, enabled=%d", num, rr_framework_enabled());

    if (g_in_rr_hook) {
        return -1;
    }
    g_in_rr_hook = true;

    if (!rr_framework_enabled()) {
        g_in_rr_hook = false;
        return -1;
    }
    fprintf(stderr, "[RAW-SYSCALL] PID=%d NR=%d\n", getpid(), num);

    RR_VERBOSE("RR_DO_SYSCALL: Framework enabled, mode=%d", g_rr_framework->mode);

    /**
     * NOTE: Syscall tree recording is handled in post-hook only to ensure
     * return values are available and correct.
     */

    /**
     * [EARLY FORK] In fuzzing mode, enter the fork server loop before the target 
     * program executes its first syscall. This ensures that all child processes 
     * start naturally from main(), allowing for seamless replay and mutation.
     */
    if (!g_rr_framework->fork_server_entered && g_rr_framework->mode == RR_MODE_FUZZING && 
        g_rr_framework->fork_server_active) {
        
        g_rr_framework->fork_server_entered = true;
        RR_INFO("[EARLY FORK] Entering fork server BEFORE first syscall");
        RR_INFO("[EARLY FORK] This ensures child processes replay from main()");
        
        int fork_result = rr_fork_server_loop();
        
        if (fork_result < 0) {
            RR_INFO("🔄 Fork server received quit command, exiting");
            exit(0);
        } else if (fork_result == 2) {
            /* Result 2 means "Advance State" (Checkpointing) */
            RR_INFO("⏩ [CHECKPOINT] Parent received ADVANCE command. Target: %u", 
                    g_rr_framework->checkpoint_target);
            /* Fall through to let parent execute syscalls until target is reached */
        } else if (fork_result > 0) {
            RR_INFO("🔄 Child process %d will now execute syscalls from the beginning", getpid());
        } else {
            RR_INFO("🔄 Parent process %d continuing in fork server loop", getpid());
        }
    }

    /* Syscall entry hint for debugging */
    // const char* syscall_name = get_syscall_name(num);

    
    if (
#ifdef TARGET_NR_exit_group
        num == TARGET_NR_exit_group
#endif
#if defined(TARGET_NR_exit_group) && defined(TARGET_NR_exit)
        ||
#endif
#ifdef TARGET_NR_exit
        num == TARGET_NR_exit
#endif
    ) {
        /* RR_INFO("=== EXIT SYSCALL DETECTED: %s (%d) ===", syscall_name, num); */
        if (g_rr_framework->mode == RR_MODE_RECORD) {
            abi_long args[8] = {
                *arg1, *arg2, *arg3, *arg4,
                *arg5, *arg6, *arg7, *arg8
            };
            rr_record_syscall(env, num, args, *arg1);
        }
    }

    abi_long args[8] = {*arg1, *arg2, *arg3, *arg4, *arg5, *arg6, *arg7, *arg8};
    abi_long ret = -1;

    /* Apply stabilization if enabled (auto-enabled for record/fuzzing) */
    if (g_rr_framework->mode != RR_MODE_DISABLED) {
        bool is_fatal_sigaction = false;
#ifdef TARGET_NR_sigaction
        if (num == TARGET_NR_sigaction) is_fatal_sigaction = true;
#endif
#ifdef TARGET_NR_rt_sigaction
        if (num == TARGET_NR_rt_sigaction) is_fatal_sigaction = true;
#endif
        if (is_fatal_sigaction) {
            int sig = (int)args[0];
            /* 
             * Do not intercept SIGILL. OpenSSL uses it to probe CPU capabilities.
             * If intercepted, the guest will crash when it executes an illegal instruction.
             */
            if (sig == TARGET_SIGSEGV || sig == TARGET_SIGABRT || sig == TARGET_SIGBUS) {
                if (g_rr_debug.level >= RR_DEBUG_INFO) {
                    fprintf(stderr, "[FUZZ-STABILIZE] Intercepting fatal signal handler (sig=%d). Returning 0.\n", sig);
                }
                g_in_rr_hook = false;
                return 0; /* Succeed without registering handler */
            }
        }
#ifdef TARGET_NR_bind
        if (num == TARGET_NR_bind) {
            rr_stabilize_bind(env, *arg2, *arg3);
        }
#endif
#ifdef TARGET_NR_chdir
        if (num == TARGET_NR_chdir) {
            rr_stabilize_chdir(env, *arg1);
        }
#endif
    }

    switch (g_rr_framework->mode) {
        case RR_MODE_RECORD:
            /* Record mode: execute original syscall, then record result */
            
            ret = -1; // Return -1 to let caller execute original logic
            break;

        case RR_MODE_REPLAY:
            /* Replay mode: select replay method based on type */
            RR_VERBOSE("RR_DO_SYSCALL: Checking if strace replay is enabled...");
            if (rr_strace_replay_enabled()) {
                RR_VERBOSE("RR_DO_SYSCALL: ABOUT TO CALL rr_replay_syscall_strace for syscall %d", num);
                ret = rr_replay_syscall_strace(env, num, args);
                RR_VERBOSE("RR_DO_SYSCALL: rr_replay_syscall_strace returned %d", (int)ret);
            } else {
                RR_VERBOSE("RR_DO_SYSCALL: STRACE REPLAY DISABLED - Calling rr_replay_syscall for syscall %d", num);
                ret = rr_replay_syscall(env, num, args);
                RR_VERBOSE("RR_DO_SYSCALL: rr_replay_syscall returned %d", (int)ret);
            }
            break;

        case RR_MODE_FUZZING:
        case RR_MODE_REPLAY_ADVANCE:
            /* CHECKPOINT RE-ENTRY LOGIC */
            /* If we have a checkpoint target and we reached it, re-enter fork server loop */
            if (g_rr_framework->checkpoint_target > 0 && 
                g_rr_framework->replay_index >= g_rr_framework->checkpoint_target) {
                
                RR_INFO("🛑 [CHECKPOINT] Reached target index %u (target=%u). Re-entering Fork Server.", 
                        g_rr_framework->replay_index, g_rr_framework->checkpoint_target);
                fflush(stderr);
                
                g_rr_framework->checkpoint_target = 0;
                g_rr_framework->silent_replay_mode = false;
                
                /* CHECKPOINT FIX: Signal fork server to resume previous 'C' command logic */
                g_rr_framework->resume_from_checkpoint = true;
                
                int fork_result = rr_fork_server_loop();
                
                if (fork_result < 0) {
                    exit(0);
                } else if (fork_result == 2) {
                    RR_INFO("⏩ [CHECKPOINT] Parent needing to ADVANCE further to %u", 
                            g_rr_framework->checkpoint_target);
                } else if (fork_result > 0) {
                    RR_INFO("🔄 Child process continuing from checkpoint via fallthrough");
                }
            }

            /**
             * Autonomous Nested Fork: For deep-fuzzing (depth > 0), identify new 
             * fork points within child processes to explore deeper execution paths.
             */
            if (g_rr_framework->is_autonomous_child && 
                rr_should_nested_fork(num, get_syscall_name(num), ret)) {
                rr_autonomous_nested_fork(g_rr_framework->replay_index);
            }

            /* Fuzzing mode: may modify parameters, then replay */
            /* Select replay function based on whether strace mode is enabled */
            if (rr_strace_replay_enabled()) {
                ret = rr_replay_syscall_strace_optimized(env, num, args);
            } else {
                ret = rr_replay_syscall(env, num, args);
            }
            
            // Baseline mode: exit after first IO syscall (fork point)
            if (g_rr_framework->baseline_mode && is_io_syscall(num)) {
                RR_INFO("Baseline mode: reached first IO syscall %s at index %u, exiting",
                        get_syscall_name(num), g_rr_framework->replay_index);
                exit(0);
            }

#ifdef TARGET_NR_ioctl
            /* Stabilize native network ioctls on diverged paths to prevent environment check failures */
            if (ret == -1 && num == TARGET_NR_ioctl) {
                int cmd = (int)args[1];
                /* Socket ioctls (SIOC*) typically have 0x89 as the high byte */
                if ((cmd >> 8) == 0x89) {
                    if (g_rr_debug.level >= RR_DEBUG_INFO) {
                        fprintf(stderr, "[FUZZ-STABILIZE] Mocking native network ioctl cmd=0x%x to return 0\n", cmd);
                    }
                    ret = 0;
                }
            }
#endif

            /* Stop native execution if it drops back to the event loop or waits for more data.
             * Prevents child from hanging indefinitely on diverged paths.
             */
            if (ret == -1) {
                bool is_event_loop = false;
#ifdef TARGET_NR_epoll_wait
                if (num == TARGET_NR_epoll_wait) is_event_loop = true;
#endif
#ifdef TARGET_NR_epoll_pwait
                if (num == TARGET_NR_epoll_pwait) is_event_loop = true;
#endif
#ifdef TARGET_NR_accept
                if (num == TARGET_NR_accept) is_event_loop = true;
#endif
#ifdef TARGET_NR_accept4
                if (num == TARGET_NR_accept4) is_event_loop = true;
#endif
#ifdef TARGET_NR_select
                if (num == TARGET_NR_select) is_event_loop = true;
#endif
#ifdef TARGET_NR__newselect
                if (num == TARGET_NR__newselect) is_event_loop = true;
#endif
#ifdef TARGET_NR_pselect6
                if (num == TARGET_NR_pselect6) is_event_loop = true;
#endif
#ifdef TARGET_NR_recv
                if (num == TARGET_NR_recv) is_event_loop = true;
#endif
#ifdef TARGET_NR_recvfrom
                if (num == TARGET_NR_recvfrom) is_event_loop = true;
#endif
#ifdef TARGET_NR_recvmsg
                if (num == TARGET_NR_recvmsg) is_event_loop = true;
#endif
#ifdef TARGET_NR_socketcall
                if (num == TARGET_NR_socketcall) {
                    int call = (int)args[0];
                    if (call == TARGET_SYS_ACCEPT || call == TARGET_SYS_ACCEPT4 || 
                        call == TARGET_SYS_RECV || call == TARGET_SYS_RECVFROM || 
                        call == TARGET_SYS_RECVMSG) {
                        is_event_loop = true;
                    }
                }
#endif
                if (is_event_loop) {
                    if (g_rr_debug.level >= RR_DEBUG_INFO) {
                        fprintf(stderr, "[FUZZ-STABILIZE] Diverged path reached blocking IO syscall %d. Terminating cleanly.\n", num);
                    }
                    exit(0);
                }
            }
            
            break;

        default:
            ret = -1;
            break;
    }
    /* Write back modified parameters to pointers */
    *arg1 = args[0]; *arg2 = args[1]; *arg3 = args[2]; *arg4 = args[3];
    *arg5 = args[4]; *arg6 = args[5]; *arg7 = args[6]; *arg8 = args[7];

    /* IO Mutation return value override is handled in rr_replay_syscall() */
    /* NOTE: ret is already the overridden value, handled by rr_replay.c */

    /* Syscall exit hint for debugging */
    RR_INFO("=== EXITING SYSCALL: %s (%d) === RETURN: %d ===",
            syscall_name, num, (int)ret);
    
    g_in_rr_hook = false;
    return ret;
}

/**
 * @brief Handles address mapping after mmap syscall execution.
 * 
 * In replay/fuzzing mode, mmap return addresses may differ from the record stage 
 * due to ASLR. This function establishes a mapping from the recorded address to
 * the actual address, used by subsequent memory syscalls (munmap, mprotect, etc.).
 * 
 * @param recorded_addr Address returned by mmap during record (read from trace).
 * @param actual_addr Actual address returned by mmap during replay.
 * 
 * @note Called in post-hook to ensure mmap has actually executed.
 * @note Mapping info is stored in the global mapping manager.
 * 
 * @warning Must be called immediately after mmap execution.
 * 
 * @see rr_addr_mapping_add() Mapping manager add function.
 * @see rr_syscall_post_hook() Caller function.
 * @see g_pending_mmap_recorded_addr Global storing recorded_addr.
 */
void rr_handle_mmap_post(target_ulong recorded_addr, target_ulong actual_addr)
{
    if (recorded_addr != actual_addr) {
        /* Check if mapping exists (possible bug in trace reuse) */
        target_ulong existing = rr_addr_mapping_get(recorded_addr);
        if (existing != recorded_addr && existing != actual_addr) {
            RR_WARN("Overwriting existing mmap mapping: 0x%lx -> 0x%lx (old) with 0x%lx -> 0x%lx (new), size=%lu",
                    (unsigned long)recorded_addr, (unsigned long)existing,
                    (unsigned long)recorded_addr, (unsigned long)actual_addr,
                    (unsigned long)g_pending_mmap_length);
        }
        
        rr_addr_mapping_add(recorded_addr, actual_addr, g_pending_mmap_length);
        RR_INFO("mmap address remapped: 0x%lx -> 0x%lx, size=%lu", 
                (unsigned long)recorded_addr, (unsigned long)actual_addr,
                (unsigned long)g_pending_mmap_length);
    }
}

/**
 * @brief Universal Hook function after syscall execution.
 * 
 * Called after QEMU executes a syscall, handling various side effects:
 * - **Record Mode**: Record return values and output data to trace.
 * - **FD Management**: Update FD mapping (open, close, dup, etc.).
 * - **Address Mapping**: Handle mmap/munmap/mremap address mappings.
 * - **Fuzzing Stats**: Update execution statistics in fuzzing mode.
 * 
 * **Mainly Handled Syscalls**:
 * - File Ops: open, openat, close, dup, dup2, dup3
 * - Memory Management: mmap, mmap2, munmap, mremap, mprotect
 * - Networking: socket, accept, accept4
 * - Process Management: fork, vfork, clone
 * 
 * @param env CPU architecture state pointer.
 * @param num Syscall number.
 * @param ret Syscall return value.
 * @param arg1-arg8 The 8 syscall argument values (NOTE: these are values, not pointers).
 * 
 * @note This is a post-hook, called AFTER syscall execution.
 * @note Unlike `rr_do_syscall`, arg1-arg8 here are values.
 * @note Contains a large switch-case structure (L900+) for varied syscall handling.
 * 
 * @warning This function has no return value and cannot stop subsequent QEMU processing.
 * @warning Contains significant switch-case logic; overlaps with `rr_syscall_dispatch.c`.
 * 
 * @see rr_do_syscall() Corresponding pre-hook.
 * @see rr_syscall_dispatch.c Modular syscall handling.
 * @see rr_record_syscall() Recording syscall in record mode.
 * @see rr_fd_mapping_add() FD mapping management.
 */
void rr_syscall_post_hook(CPUArchState *env, int num, abi_long ret,
                          abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8)
{
    RR_VERBOSE("POST_HOOK: syscall=%d, ret=%ld", num, (long)ret);
    
    if (g_in_rr_hook) {
        return; // Already in hook
    }
    g_in_rr_hook = true;

    if (!rr_framework_enabled()) {
        RR_VERBOSE("POST_HOOK: Skipping syscall %d - framework not enabled", num);
        goto cleanup;
    }

    /* Record syscall node to tree structure */
    if (g_rr_framework) {
        uint64_t args_arr[6] = {
            (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
            (uint64_t)arg4, (uint64_t)arg5, (uint64_t)arg6
        };
        uint32_t current_idx = (g_rr_framework->mode == RR_MODE_RECORD) ? 
                               g_rr_framework->trace_length : g_rr_framework->replay_index;
        
        /* Detect if this syscall was mutated in fuzzing mode */
        bool was_mutated = false;
        
        if (g_rr_framework->mode == RR_MODE_FUZZING) {
            /* Check if mutation occurred during replay of this syscall */
            if (g_rr_framework->last_syscall_mutated) {
                was_mutated = true;
                RR_VERBOSE("POST_HOOK: Syscall #%u was mutated (flag detected)", current_idx);
                
                /* Reset flag */
                g_rr_framework->last_syscall_mutated = false;
            }
        }

        // Redundant g_instruction_count check removed (IsMutated handled by last_syscall_mutated flag)
        
        uint32_t node_id = rr_tree_add_syscall_node(
            getpid(),                               // PID
            current_idx,                            // syscall_index
            num,                                     // syscall_nr
            get_syscall_name(num),                  // syscall_name
            args_arr,                                // args
            ret,                                     // retval
            0,                                       // timestamp_enter (auto)
            0,                                       // timestamp_exit (auto)
            was_mutated                              /* is_mutated flag */
        );

        /* ✅ Attach Basic Block Trace to Syscall Node */
        if (rr_bb_trace_is_enabled()) {
            uint64_t bbs[128];
            uint32_t count = rr_bb_trace_get_current_buffer(bbs, 128);
            if (count > 0) {
                // Attach to tree node
                rr_tree_set_node_bbs(node_id, bbs, count);
                // Flush buffer to ensure next syscall gets fresh BBs
                rr_bb_trace_flush();
            }
        }

        /* Detect fork syscall and record fork relation */
        int fork_nr = -1, vfork_nr = -1, clone_nr = -1;
#if defined(TARGET_NR_fork)
        fork_nr = TARGET_NR_fork;
#endif
#if defined(TARGET_NR_vfork)
        vfork_nr = TARGET_NR_vfork;
#endif
#if defined(TARGET_NR_clone)
        clone_nr = TARGET_NR_clone;
#endif
        if ((num == fork_nr || num == vfork_nr || num == clone_nr) && ret > 0) {
            rr_tree_add_fork_relation(node_id, (uint32_t)ret);
            RR_VERBOSE("Recorded fork relation: parent_node=%u, child_pid=%u", node_id, (uint32_t)ret);
        }
    }

    if (g_rr_framework->mode == RR_MODE_RECORD) {
        /* Record mode: record syscall result */
        RR_VERBOSE("POST_HOOK: Recording syscall %d with ret=%d", num, (int)ret);
        abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};

        int record_result = rr_record_syscall(env, num, args, ret);
        if (record_result == 0) {
            g_rr_framework->total_syscalls++;
            RR_VERBOSE("POST_HOOK: Successfully recorded syscall %d (total: %lu)", num, g_rr_framework->total_syscalls);
        } else {
            RR_ERROR("POST_HOOK: Failed to record syscall %d (result=%d)", num, record_result);
        }
        goto cleanup;
    }
    
    if (g_rr_framework->mode == RR_MODE_REPLAY || g_rr_framework->mode == RR_MODE_FUZZING) {
        /* Replay mode: handle FD mapping */
        
        /* Ensure strace post_hook runs before checking flags */
        if (rr_strace_replay_enabled()) {
            abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
            rr_strace_syscall_post_hook(env, num, ret, args);
        }
        
        /* CHECK: If this syscall was already consumed in rr_replay_syscall 
         * (record read and index incremented), do not process again to avoid duplication. */
        if (g_syscall_already_consumed) {
            syscall_record_t *record = g_pending_post_record;
            g_syscall_already_consumed = false;
            g_pending_post_record = NULL;

            if (record) {
                /* Deviation detection - verify return value matches trace */
                if (record->retval != ret) {
                    if (is_expected_deviation(num, record->retval, ret)) {
                        /* Expected deviation (e.g., ASLR); log at VERBOSE level only */
                        RR_VERBOSE("Expected deviation: syscall=%d (%s), recorded=0x%lx, actual=0x%lx",
                                   num, get_syscall_name(num), 
                                   (unsigned long)record->retval, (unsigned long)ret);
                    } else {
                        /* Unexpected deviation, issue warning */
                        RR_WARN("UNEXPECTED DEVIATION: syscall=%d (%s), recorded_ret=%ld, actual_ret=%ld (diff=%ld)",
                                num, get_syscall_name(num), (long)record->retval, (long)ret, (long)(ret - record->retval));
                        g_rr_framework->deviation_count++;
                    }
                }

                switch (num) {
#ifdef TARGET_NR_open
                case TARGET_NR_open:
#endif
                case TARGET_NR_openat:
#ifdef TARGET_NR_creat
                case TARGET_NR_creat:
#endif
                case TARGET_NR_dup:
#ifdef TARGET_NR_dup2
                case TARGET_NR_dup2:
#endif
#ifdef TARGET_NR_dup3
                case TARGET_NR_dup3:
#endif
#ifdef TARGET_NR_socket
                case TARGET_NR_socket:
#endif
#ifdef TARGET_NR_accept
                case TARGET_NR_accept:
#endif
#ifdef TARGET_NR_accept4
                case TARGET_NR_accept4:
#endif
                    if (ret >= 0) {
                        RR_INFO("🔗 FD_MAPPING: Adding mapping recorded_fd=%d -> actual_fd=%d",
                                (int)record->retval, (int)ret);
                        rr_fd_mapping_add(record->retval, (int)ret);
                    }
                    break;

#ifdef TARGET_NR_close
                case TARGET_NR_close:
                    if (ret == 0) {
                        rr_fd_mapping_remove((int)record->args[0]);
                    }
                    break;
#endif

#ifdef TARGET_NR_pipe
                case TARGET_NR_pipe:
#endif
#ifdef TARGET_NR_pipe2
                case TARGET_NR_pipe2:
#endif
                    if (ret == 0 && record->arg_data[0]) {
                        int recorded_fds[2];
                        memcpy(recorded_fds, record->arg_data[0], sizeof(recorded_fds));
                        int actual_fds[2];
                        target_ulong guest_ptr = (target_ulong)record->args[0];
                        if (cpu_memory_rw_debug(env_cpu(env), guest_ptr, (uint8_t *)actual_fds,
                                                sizeof(actual_fds), 0) == 0) {
                            rr_fd_mapping_add(recorded_fds[0], actual_fds[0]);
                            rr_fd_mapping_add(recorded_fds[1], actual_fds[1]);
                        }
                    }
                    break;

#ifdef TARGET_NR_mmap
                case TARGET_NR_mmap:
#endif
#ifdef TARGET_NR_mmap2
                case TARGET_NR_mmap2:
#endif
                    if (g_pending_mmap_recorded_addr != 0) {
                        if (ret > 0) {
                            rr_handle_mmap_post(g_pending_mmap_recorded_addr, (target_ulong)ret);
                        } else {
                            RR_ERROR("POST_HOOK: mmap failed, recorded=0x%lx, ret=%ld",
                                     (unsigned long)g_pending_mmap_recorded_addr, (long)ret);
                        }
                        g_pending_mmap_recorded_addr = 0;
                        g_pending_mmap_length = 0;
                    }
                    break;

#ifdef TARGET_NR_munmap
                case TARGET_NR_munmap:
                    if (ret == 0) {
                        rr_addr_mapping_remove((target_ulong)record->args[0]);
                    }
                    break;
#endif

#ifdef TARGET_NR_mremap
                case TARGET_NR_mremap:
                    if (ret != (abi_long)-1) {
                        rr_addr_mapping_remove((target_ulong)record->args[0]);
                        rr_handle_mmap_post((target_ulong)record->args[0], (target_ulong)ret);
                    }
                    break;
#endif

#ifdef TARGET_NR_brk
                case TARGET_NR_brk:
                    if (ret != (abi_long)-1 && record->has_aux_data) {
                        rr_aux_data_t *aux = rr_aux_find(record->aux_data, 0);
                        if (aux && aux->size == sizeof(abi_long)) {
                            abi_long recorded_brk;
                            memcpy(&recorded_brk, aux->data, sizeof(recorded_brk));
                            rr_addr_mapping_add((target_ulong)recorded_brk, (target_ulong)ret, 0);
                        }
                    }
                    break;
#endif

                default:
                    break;
                }

                /* Dynamic trace: Syscall exit (Hybrid path) */
#ifdef RR_ENABLE_DYNAMIC_TRACE
                rr_dynamic_trace_syscall_exit(env, num, (uint64_t*)&arg1, ret,
                                                g_rr_framework->replay_index - 1, 0);
#endif

                rr_record_dispose(record);
            }
            goto cleanup;
        }

        if (
#ifdef TARGET_NR_mmap
            num == TARGET_NR_mmap
#ifdef TARGET_NR_mmap2
            ||
#endif
#endif
#ifdef TARGET_NR_mmap2
            num == TARGET_NR_mmap2
#endif
        ) {
            if (g_pending_mmap_recorded_addr != 0 && ret > 0) {
                rr_handle_mmap_post(g_pending_mmap_recorded_addr, (target_ulong)ret);
            }
            g_pending_mmap_recorded_addr = 0;
            g_pending_mmap_length = 0;
        }

        /* Always send EXIT message to preserve tree visualization integrity */
        abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
        rr_dynamic_trace_syscall_exit(env, num, (uint64_t*)args, ret,
                                       g_rr_framework->replay_index - 1, false);  // -1 because it's already incremented
        
        RR_VERBOSE("POST_HOOK: Replay mode, syscall=%d, ret=%d", num, (int)ret);
        goto cleanup;
    }

cleanup:
    g_in_rr_hook = false;
}