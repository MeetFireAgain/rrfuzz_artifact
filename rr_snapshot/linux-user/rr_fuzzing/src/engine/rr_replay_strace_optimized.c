/**
 * Optimized RR-Fuzz Strace Replay Module
 * Modular design with optimized data structures.
 */

#include "rr_framework.h"
#include "rr_constants.h"
#include "rr_syscallparser.h"
#include "rr_replay_strace.h"
#include "rr_syscall_dispatch.h"
#include "rr_mapping_manager.h"
#include "rr_dynamic_trace.h"  /* Dynamic trace API */
#include "qemu.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>

/* Global State Management */

/* Strace parser instance */
static rr_strace_parser_t *g_strace_parser = NULL;

/* Global syscall index (used by fork server) */
uint32_t g_strace_current_index = 0;

/* Replay control state - Simplified version */
typedef struct {
    bool enabled;
    bool strict_mode;
    bool skip_unmatched;
    int max_lookahead;

    /* Statistics */
    uint64_t total_syscalls;
    uint64_t matched_syscalls;
    uint64_t skipped_syscalls;
    uint64_t error_syscalls;
    uint64_t fallback_syscalls;

    /* Status information */
    char *trace_filename;
    size_t current_record_index;
    bool trace_exhausted;
    bool allow_fallback_execution;

    /* Track mutation state for the current syscall */
    bool current_syscall_was_fuzzed;
} rr_strace_replay_state_t;

static rr_strace_replay_state_t g_strace_state = {0};
static char g_stats_filename[256] = {0};

/* Statistics output control */
#define STATS_PRINT_INTERVAL 10
static size_t g_last_stats_print = 0;

/* Current record being processed (strace-specific, distinct from binary replay g_current_record) */
__attribute__((unused)) static rr_strace_record_t *g_current_strace_record = NULL;
static rr_strace_record_t *g_current_record_strace = NULL;  /* For post_hook usage */

/* Signal handler flag */
static volatile sig_atomic_t g_signal_received = 0;

/* Logging System */

typedef enum {
    STRACE_LOG_ERROR = 0,
    STRACE_LOG_WARN = 1,
    STRACE_LOG_INFO = 2,
    STRACE_LOG_VERBOSE = 3,
    STRACE_LOG_DEBUG = 4
} strace_log_level_t;

static strace_log_level_t g_strace_log_level = STRACE_LOG_INFO;

static void init_strace_log_level(void) {
    const char *level_str = getenv("RR_STRACE_LOG_LEVEL");
    if (!level_str) return;
    
    if (strcmp(level_str, "ERROR") == 0 || strcmp(level_str, "0") == 0) {
        g_strace_log_level = STRACE_LOG_ERROR;
    } else if (strcmp(level_str, "WARN") == 0 || strcmp(level_str, "1") == 0) {
        g_strace_log_level = STRACE_LOG_WARN;
    } else if (strcmp(level_str, "INFO") == 0 || strcmp(level_str, "2") == 0) {
        g_strace_log_level = STRACE_LOG_INFO;
    } else if (strcmp(level_str, "VERBOSE") == 0 || strcmp(level_str, "3") == 0) {
        g_strace_log_level = STRACE_LOG_VERBOSE;
    } else if (strcmp(level_str, "DEBUG") == 0 || strcmp(level_str, "4") == 0) {
        g_strace_log_level = STRACE_LOG_DEBUG;
    }
}

/* 
 * Strace module specific logging macros - avoids conflict with framework macros.
 * Uses STRACE_ prefix for differentiation.
 */
#define STRACE_ERROR(fmt, ...)   do { if (g_strace_log_level >= STRACE_LOG_ERROR) fprintf(stderr, "[STRACE-ERROR] " fmt "\n", ##__VA_ARGS__); } while(0)
#define STRACE_WARN(fmt, ...)    do { if (g_strace_log_level >= STRACE_LOG_WARN) fprintf(stderr, "[STRACE-WARN] " fmt "\n", ##__VA_ARGS__); } while(0)
#define STRACE_INFO(fmt, ...)    do { if (g_strace_log_level >= STRACE_LOG_INFO) fprintf(stderr, "[STRACE-INFO] " fmt "\n", ##__VA_ARGS__); } while(0)
#define STRACE_VERBOSE(fmt, ...) do { if (g_strace_log_level >= STRACE_LOG_VERBOSE) fprintf(stderr, "[STRACE-VERBOSE] " fmt "\n", ##__VA_ARGS__); } while(0)
#define STRACE_DEBUG(fmt, ...)   do { if (g_strace_log_level >= STRACE_LOG_DEBUG) fprintf(stderr, "[STRACE-DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)

/* Statistics and Signal Handling */

static void rr_strace_signal_handler(int sig);

void rr_strace_save_stats_to_file(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(fp, "=== OPTIMIZED STRACE REPLAY STATISTICS ===\n");
    fprintf(fp, "Generated: %s\n", timestamp);
    fprintf(fp, "Trace file: %s\n", g_strace_state.trace_filename ? g_strace_state.trace_filename : "unknown");
    fprintf(fp, "\n");
    
    fprintf(fp, "Total syscalls: %zu\n", g_strace_state.total_syscalls);
    fprintf(fp, "Successfully matched: %zu\n", g_strace_state.matched_syscalls);
    fprintf(fp, "Skipped: %zu\n", g_strace_state.skipped_syscalls);
    fprintf(fp, "Errors: %zu\n", g_strace_state.error_syscalls);
    fprintf(fp, "Fallback executions: %zu\n", g_strace_state.fallback_syscalls);
    
    if (g_strace_state.total_syscalls > 0) {
        double match_rate = (100.0 * g_strace_state.matched_syscalls / g_strace_state.total_syscalls);
        fprintf(fp, "Match rate: %.1f%%\n", match_rate);
        fprintf(fp, "Status: %s\n", g_strace_state.trace_exhausted ? "EXHAUSTED" : "ACTIVE");
    }
    
    // Add mapping manager statistics
    rr_mapping_stats_t mapping_stats;
    rr_mapping_get_stats(&mapping_stats);
    fprintf(fp, "\nMapping Statistics:\n");
    fprintf(fp, "FD hit rate: %.1f%%\n", 
           mapping_stats.fd_lookups > 0 ? 
           (100.0 * mapping_stats.fd_hits / mapping_stats.fd_lookups) : 0.0);
    fprintf(fp, "Addr hit rate: %.1f%%\n", 
           mapping_stats.addr_lookups > 0 ? 
           (100.0 * mapping_stats.addr_hits / mapping_stats.addr_lookups) : 0.0);
    
    fprintf(fp, "=== END ===\n");
    fclose(fp);
}

void rr_strace_replay_print_stats(void) {
    if (!g_strace_state.enabled) return;
    
    STRACE_INFO("=== OPTIMIZED STRACE REPLAY STATISTICS ===");
    STRACE_INFO("📊 Basic Statistics:");
    STRACE_INFO("  Total syscalls processed: %zu", g_strace_state.total_syscalls);
    STRACE_INFO("  Successfully matched: %zu (%.1f%%)", 
            g_strace_state.matched_syscalls,
            g_strace_state.total_syscalls > 0 ? 
            (100.0 * g_strace_state.matched_syscalls / g_strace_state.total_syscalls) : 0.0);
    STRACE_INFO("  Skipped syscalls: %zu", g_strace_state.skipped_syscalls);
    STRACE_INFO("  Error syscalls: %zu", g_strace_state.error_syscalls);
    STRACE_INFO("  Fallback executions: %zu", g_strace_state.fallback_syscalls);
    
    // Display mapping statistics
    rr_mapping_print_stats();
    
    STRACE_INFO("=== END STATISTICS ===");
    fflush(stdout);
    fflush(stderr);
}

static void rr_strace_signal_handler(int sig) {
    g_signal_received = 1;
    STRACE_INFO("🚨 Signal %d received, printing final statistics...", sig);
    
    char stats_filename[256];
    snprintf(stats_filename, sizeof(stats_filename), "/tmp/rr_strace_stats_signal_%d.txt", getpid());
    rr_strace_save_stats_to_file(stats_filename);
    
    rr_strace_replay_print_stats();
    
    signal(sig, SIG_DFL);
    raise(sig);
}

static void rr_strace_check_periodic_stats(void) {
    if (g_strace_state.total_syscalls > 0 && 
        (g_strace_state.total_syscalls - g_last_stats_print) >= STATS_PRINT_INTERVAL) {
        
        if (g_stats_filename[0] != '\0') {
            rr_strace_save_stats_to_file(g_stats_filename);
        }
        
        g_last_stats_print = g_strace_state.total_syscalls;
    }
}

/* Optimized Matching Algorithm */

static rr_strace_record_t *optimized_find_matching_record(int syscall_nr, abi_long *args) {
    const char *syscall_name = rr_get_syscall_name_fast(syscall_nr);
    if (!syscall_name) {
        STRACE_WARN("Unknown syscall number: %d", syscall_nr);
        return NULL;
    }
    
    syscall_importance_t importance = rr_get_syscall_importance(syscall_nr);
    
    // Adjust search strategy based on importance
    int max_skip;
    switch (importance) {
        case SYSCALL_IMPORTANCE_CRITICAL:
            max_skip = 50;
            break;
        case SYSCALL_IMPORTANCE_IMPORTANT:
            max_skip = 30;
            break;
        case SYSCALL_IMPORTANCE_OPTIONAL:
            max_skip = 15;
            break;
        case SYSCALL_IMPORTANCE_ENVIRONMENT:
            max_skip = 5;
            break;
        default:
            max_skip = 10;
            break;
    }
    
    STRACE_VERBOSE("Optimized matching for %s (importance=%d, max_skip=%d)", 
               syscall_name, importance, max_skip);
    
    int skip_count = 0;
    rr_strace_record_t *record = NULL;
    
    while (skip_count <= max_skip) {
        record = rr_strace_parser_get_next(g_strace_parser);
        if (!record) {
            g_strace_state.trace_exhausted = true;
            
            if (importance == SYSCALL_IMPORTANCE_CRITICAL) {
                STRACE_ERROR("Critical syscall %s cannot find match, trace exhausted", syscall_name);
            } else {
                STRACE_INFO("Syscall %s - trace exhausted, fallback execution", syscall_name);
            }
            
            return NULL;
        }
        
        /* 🔥 修复：索引递增移到匹配成功后 */
        
        // === Intelligent Matching Algorithm - Three-level Strategy ===
        
        // Level 0: Syscall number must match
        if (strcmp(record->syscall_name, syscall_name) != 0) {
            skip_count++;
            /* No match: continue loop; index remains unchanged */
            continue;
        }
        
        // Level 1: Probing Match (PROBE)
        // Identifies "probing" syscalls (e.g., file access returning ENOENT)
        if ((syscall_nr == 257 || syscall_nr == 262 || syscall_nr == 21) &&  // openat/newfstatat/access
            record->ret_value == -2) {  // ENOENT
            
            STRACE_VERBOSE("✓ Probe match: %s returned ENOENT", syscall_name);
            if (skip_count > 0) {
                STRACE_INFO("Probe match successful after skipping %d records: %s", 
                        skip_count, syscall_name);
            }
            /* Match successful, increment index */
            g_strace_state.current_record_index++;
            return record;
        }
        
        // Level 2: Semantic Match (SEMANTIC)
        
        // openat success - only check access mode
        if (syscall_nr == 257 && record->ret_value >= 0) {
            // Only check access mode (low 2 bits of flags)
            if (record->arg_count > 2 && args) {
                int record_mode = record->args[2].value & 0x3;  // O_ACCMODE
                int current_mode = args[2] & 0x3;
                
                if (record_mode == current_mode) {
                    STRACE_VERBOSE("✓ Semantic match: openat mode=%s", 
                               record_mode == 0 ? "RDONLY" : 
                               record_mode == 1 ? "WRONLY" : "RDWR");
                    if (skip_count > 0) {
                        STRACE_INFO("Semantic match successful after skipping %d records: %s", 
                                skip_count, syscall_name);
                    }
                    g_strace_state.current_record_index++;
                    return record;
                }
            }
        }
        
        // newfstatat - only check flags
        if (syscall_nr == 262) {
            if (record->arg_count > 3 && args) {
                if (args[3] == record->args[3].value) {  // flags相同
                    STRACE_VERBOSE("✓ Semantic match: newfstatat flags=0x%lx", (unsigned long)args[3]);
                    if (skip_count > 0) {
                        STRACE_INFO("Semantic match successful after skipping %d records: %s", 
                                skip_count, syscall_name);
                    }
                    g_strace_state.current_record_index++;
                    return record;
                }
            }
        }
        
        // mmap - check prot and flags, ignore address and length
        if (syscall_nr == 9) {
            if (record->arg_count > 3 && args) {
                bool prot_match = (args[2] == record->args[2].value);  // prot
                bool flags_match = (args[3] == record->args[3].value); // flags
                
                if (prot_match && flags_match) {
                    STRACE_VERBOSE("✓ Semantic match: mmap prot=0x%lx flags=0x%lx", 
                               (unsigned long)args[2], (unsigned long)args[3]);
                    if (skip_count > 0) {
                        STRACE_INFO("Semantic match successful after skipping %d records: %s", 
                                skip_count, syscall_name);
                    }
                    g_strace_state.current_record_index++;
                    return record;
                }
            }
        }
        
        // Level 3: Exact Match (Fallback Strategy)
        // Syscall number already matches, return record.
        STRACE_VERBOSE("✓ Exact match: %s", syscall_name);
        if (skip_count > 0) {
            STRACE_INFO("Exact match successful after skipping %d records: %s", 
                    skip_count, syscall_name);
        }
        g_strace_state.current_record_index++;
        return record;
    }
    
    STRACE_ERROR("Optimized match failed after %d attempts for %s", max_skip + 1, syscall_name);
    return NULL;
}

/* Deterministic Syscall Handling */

/**
 * Deterministic uname handling - resolves instabilities leading to execution path divergence.
 * 
 * Logic: Returns success (0) directly instead of executing via QEMU to avoid potential 
 * fallback syscalls (e.g., reading /proc/sys/kernel/osrelease) that could break trace alignment.
 */
__attribute__((unused)) static abi_long rr_handle_deterministic_uname(CPUArchState *env, abi_long buf_addr) {
    g_strace_state.matched_syscalls++;
    STRACE_INFO("Deterministic uname: directly returning success to avoid fallback syscalls");
    
    // Return 0 (success) directly to avoid fallback and extra syscalls.
    return 0;
}

/* Main Interface Functions */

int rr_strace_replay_init(const char *trace_file) {
    init_strace_log_level();
    
    if (!trace_file) {
        STRACE_ERROR("trace_file is NULL");
        return -1;
    }
    
    STRACE_INFO("Initializing optimized strace replay with trace file: %s", trace_file);
    
    // Initialize state
    memset(&g_strace_state, 0, sizeof(g_strace_state));
    g_strace_state.trace_filename = strdup(trace_file);
    if (!g_strace_state.trace_filename) {
        STRACE_ERROR("Failed to allocate memory for trace filename");
        return -1;
    }
    
    g_strace_state.strict_mode = false;
    g_strace_state.skip_unmatched = true;
    g_strace_state.max_lookahead = 5;
    g_strace_state.trace_exhausted = false;
    g_strace_state.allow_fallback_execution = true;
    
    // Initialize syscall dispatcher
    if (rr_syscall_dispatch_init() < 0) {
        STRACE_ERROR("Failed to initialize syscall dispatcher");
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // Initialize mapping manager
    if (rr_mapping_manager_init(256, 128) < 0) {
        STRACE_ERROR("Failed to initialize mapping manager");
        rr_syscall_dispatch_cleanup();
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // Initialize strace parser
    g_strace_parser = rr_strace_parser_init(trace_file);
    if (!g_strace_parser) {
        STRACE_ERROR("Failed to initialize strace parser");
        rr_mapping_manager_cleanup();
        rr_syscall_dispatch_cleanup();
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // Load strace file
    if (rr_strace_parser_load(g_strace_parser) < 0) {
        STRACE_ERROR("Failed to load strace file");
        rr_strace_parser_cleanup(g_strace_parser);
        g_strace_parser = NULL;
        rr_mapping_manager_cleanup();
        rr_syscall_dispatch_cleanup();
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // Get statistics
    size_t total_records, current_index;
    rr_strace_get_stats(g_strace_parser, &total_records, &current_index);
    
    g_strace_state.enabled = true;
    
    // Register signal handlers
    signal(SIGINT, rr_strace_signal_handler);
    signal(SIGTERM, rr_strace_signal_handler);
    signal(SIGQUIT, rr_strace_signal_handler);
    
    // Set statistics filename
    snprintf(g_stats_filename, sizeof(g_stats_filename), "/tmp/rr_strace_optimized_stats_%d.txt", getpid());
    rr_strace_save_stats_to_file(g_stats_filename);
    
    STRACE_INFO("Optimized strace replay initialized successfully");
    STRACE_INFO("- Trace file: %s", trace_file);
    STRACE_INFO("- Total records: %zu", total_records);
    STRACE_INFO("- Stats file: %s", g_stats_filename);
    
    return 0;
}

void rr_strace_replay_cleanup(void) {
    if (!g_strace_state.enabled) return;
    
    // Save final statistics
    if (g_stats_filename[0] != '\0') {
        rr_strace_save_stats_to_file(g_stats_filename);
    }
    
    // Cleanup resources
    if (g_strace_parser) {
        rr_strace_parser_cleanup(g_strace_parser);
        g_strace_parser = NULL;
    }
    
    rr_mapping_manager_cleanup();
    rr_syscall_dispatch_cleanup();
    
    if (g_strace_state.trace_filename) {
        free(g_strace_state.trace_filename);
        g_strace_state.trace_filename = NULL;
    }
    
    memset(&g_strace_state, 0, sizeof(g_strace_state));
    
    STRACE_INFO("Optimized strace replay cleanup completed");
}

abi_long rr_replay_syscall_strace_optimized(CPUArchState *env, int num, abi_long *args) {
    STRACE_DEBUG("Processing syscall %d", num);
    
    /* DEBUG: Print silent mode status for the first syscall */
    static int first_call = 1;
    static pid_t last_pid = 0;
    pid_t current_pid = getpid();
    
    if (first_call) {
        first_call = 0;
        RR_INFO("🔍 First syscall in replay: silent_replay_mode=%d, checkpoint_target=%u",
                g_rr_framework->silent_replay_mode, g_rr_framework->checkpoint_target);
    }
    
    /* DEBUG: Detailed status print for each process's first syscall */
    if (current_pid != last_pid) {
        last_pid = current_pid;
        RR_INFO("🔍 [PID %d] First syscall: trace_exhausted=%d, current_record_index=%zu, parser=%p, enabled=%d",
                current_pid, g_strace_state.trace_exhausted, g_strace_state.current_record_index, 
                g_strace_parser, g_strace_state.enabled);
    }
    
    if (!g_strace_state.enabled) {
        STRACE_ERROR("Module not initialized");
        return -1;
    }
    
    g_strace_state.total_syscalls++;
    
    // Check if trace exhausted
    if (g_strace_state.trace_exhausted) {
        g_strace_state.fallback_syscalls++;
        const char *syscall_name = rr_get_syscall_name_fast(num);
        STRACE_VERBOSE("Trace exhausted, fallback execution for %s (%zu total fallbacks)", 
                  syscall_name ? syscall_name : "unknown", g_strace_state.fallback_syscalls);
        
        /* Trace exhausted in Fuzzing mode child process should exit */
        if (g_rr_framework && 
            g_rr_framework->mode == RR_MODE_FUZZING && 
            g_rr_framework->child_pid == 0) {
            STRACE_INFO("Trace exhausted in child process (PID=%d), exiting normally", getpid());
            exit(0);  /* Child exits; parent waitpid() will return */
        }
        
        return -1;
    }
    
    // Check periodic statistics
    rr_strace_check_periodic_stats();
    
    // Find matching record
    rr_strace_record_t *record = optimized_find_matching_record(num, args);
    
    /* uname handling: execute real uname if not found in trace for compatibility */
    if (!record && num == 63) { // TARGET_NR_uname
        STRACE_INFO("uname not found in trace, executing real uname for environment compatibility");
        g_strace_state.fallback_syscalls++;
        return -1; // Fallback to host execution
    }
    if (!record) {
        g_strace_state.error_syscalls++;
        const char *syscall_name = rr_get_syscall_name_fast(num);
        STRACE_WARN("No matching record found for %s (%d)", 
                syscall_name ? syscall_name : "unknown", num);
        
        /* Exit child process in Fuzzing mode if too many unmatched syscalls */
        if (g_rr_framework && 
            g_rr_framework->mode == RR_MODE_FUZZING && 
            g_rr_framework->child_pid == 0 && 
            g_strace_state.error_syscalls > 5) {  // Tolerance limit
            STRACE_WARN("Too many unmatched syscalls in child process (%zu errors), exiting", 
                   g_strace_state.error_syscalls);
            exit(1);  /* Abnormal exit; parent will detect */
        }
        
        if (g_strace_state.skip_unmatched) {
            return -1;
        } else {
            errno = ENOSYS;
            return -1;
        }
    }
    
    g_strace_state.matched_syscalls++;
    
    /* Update global index and framework index */
    g_strace_current_index = g_strace_state.current_record_index;
    if (g_rr_framework) {
        g_rr_framework->replay_index = g_strace_state.current_record_index;
    }
    
    STRACE_VERBOSE("Found matching record: %s, ret=%ld", record->syscall_name, record->ret_value);

    /* Initialize mutation state to false */
    g_strace_state.current_syscall_was_fuzzed = false;

    /* Dynamic Tracking: Syscall Enter (Skipped in silent mode) */
    if (!g_rr_framework->silent_replay_mode) {
        rr_dynamic_trace_syscall_enter(
            env, 
            num, 
            (uint64_t*)args, 
            g_strace_state.current_record_index,
            false  /* Not mutated yet */
        );
    } else {
        RR_INFO("🔇 Silent mode: skipping trace for syscall[%u] %s", 
                g_strace_state.current_record_index, record->syscall_name);
    }
    
    /* 🔥 修复：uname 不使用固定字符串，从 trace 获取或返回 -1 让宿主执行 */
    
    // Save original arguments for comparison
    abi_long orig_args[RR_MAX_SYSCALL_ARGS];
    for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
        orig_args[i] = args[i];
    }
    (void)orig_args;  /* Prevents unused-variable warning when debug is disabled */
    
    // Step 1: Apply recorded arguments and FD mapping (from trace)
    rr_apply_syscall_args_optimized(record, args);
    rr_apply_fd_mapping_optimized(num, args);
    
    // Log trace parameter modification details
    bool args_modified = false;
    for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
        if (orig_args[i] != args[i]) {
            args_modified = true;
            STRACE_DEBUG("TRACE_REPLAY: %s arg[%d] %ld -> %ld", 
                    record->syscall_name, i, (long)orig_args[i], (long)args[i]);
        }
    }
    
    if (args_modified) {
        STRACE_DEBUG("TRACE_REPLAY: %s parameter replacement from trace completed", record->syscall_name);
    }
    
    /* Fuzz Mutation Injection Point */
    /* 
     * Step 2: In Fuzzing mode, mutate replayed parameters.
     * 
     * Execution Order:
     * 1. Parameters restored from trace (completed above).
     * 2. Apply Fuzz mutations (here).
     * 3. Execute real syscall (return -1 below).
     * 
     * Note: g_rr_framework might be NULL in pure strace mode.
     */
    if (g_rr_framework && g_rr_framework->mode == RR_MODE_FUZZING) {
        // Use strace record index as syscall_index
        uint32_t syscall_index = (uint32_t)g_strace_state.current_record_index;
        
        STRACE_VERBOSE("Applying fuzz mutations at syscall_index=%u (%s)", 
                   syscall_index, record->syscall_name);
        
        /* Save current parameters, detect changes after mutation */
        abi_long pre_fuzz_args[RR_MAX_SYSCALL_ARGS];
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
            pre_fuzz_args[i] = args[i];
        }
        (void)pre_fuzz_args;  /* Prevents unused-variable warning when debug is disabled */
        
        // Mutate syscall parameters using Fuzz engine
        int mutation_result = rr_fuzz_mutate_syscall(env, syscall_index, args, num);
 
        // Detect if parameters were mutated (including buffer mutations indicated by return value)
        bool fuzz_modified = (mutation_result > 0);  // Buffer mutations
 
        // Additional check for argument changes (for debugging/statistics)
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
            if (pre_fuzz_args[i] != args[i]) {
                fuzz_modified = true;  // Any argument change counts as mutation
                STRACE_VERBOSE("FUZZ_MUTATED: %s arg[%d] %ld -> %ld",
                          record->syscall_name, i, (long)pre_fuzz_args[i], (long)args[i]);
            }
        }
        
        if (fuzz_modified) {
            STRACE_INFO("FUZZING: %s at index %u - parameters mutated",
                   record->syscall_name, syscall_index);
        }
 
        // Save mutation state for dynamic tracking
        g_strace_state.current_syscall_was_fuzzed = fuzz_modified;
    }
    
    // Save current record for POST-HOOK
    g_current_record_strace = record;
 
    /* Set flag to indicate that this record has been consumed */
    g_syscall_already_consumed = true;
 
    /* Check for IO return value overrides */
    if (g_rr_framework && g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_retval_override()) {
        abi_long original_ret = record->ret_value;
        abi_long mutated_ret = rr_fuzz_get_retval_override();  /* Clears the flag */
 
        RR_INFO("IO RETVAL OVERRIDE: %s: %ld → %ld (Executing mutated retval instead of real syscall)",
                record->syscall_name, original_ret, mutated_ret);
 
        fprintf(stderr, "[STRACE] RETVAL OVERRIDE: %s %ld → %ld (Pure replay with mutated retval)\n",
                record->syscall_name, (long)original_ret, (long)mutated_ret);
        fflush(stderr);
 
        // Directly return mutated value without executing real syscall. 
        // Essential for IO syscalls to control return values and trigger different code paths.
        return mutated_ret;
    }
 
    STRACE_VERBOSE("Hybrid replay+fuzz mode: executing real syscall with modified args");
    return -1;  // Return -1 to allow QEMU to execute real syscall
}

void rr_strace_syscall_post_hook_optimized(CPUArchState *env, int num, abi_long ret, abi_long *args) {
    if (!g_strace_state.enabled || !g_current_record_strace) {
        return;
    }
    
    const char *syscall_name = rr_get_syscall_name_fast(num);
    STRACE_DEBUG("Optimized post-hook for %s, ret=%ld", 
             syscall_name ? syscall_name : "unknown", (long)ret);
    
    // Use optimized POST treatment
    rr_syscall_post_hook_optimized(num, g_current_record_strace, ret, args);
    
    /* Dynamic Tracking: Syscall Exit (Skipped in silent mode) */
    if (!g_rr_framework->silent_replay_mode) {
        // Use actual mutation state instead of global mode
        bool was_fuzzed = g_strace_state.current_syscall_was_fuzzed;
        rr_dynamic_trace_syscall_exit(
            env,
            num,
            (uint64_t*)args,
            ret,
            g_strace_state.current_record_index,
            was_fuzzed
        );
    }
    
    /* Check if fork_point reached to disable silent mode */
    if (g_rr_framework->silent_replay_mode) {
        uint32_t target_fork_point = g_rr_framework->checkpoint_target;  /* fork_point stored here */
        if (g_strace_state.current_record_index >= target_fork_point) {
            g_rr_framework->silent_replay_mode = false;
            RR_INFO("Reached fork_point[%u], switching to normal mode", target_fork_point);
            
            // Send iteration message (Child officially starts)
            if (g_dynamic_trace_pipe_fd >= 0) {
                rr_dynamic_trace_iteration(g_rr_framework->current_iteration_id, getpid());
            }
        }
    }
    
    // Cleanup current record
    g_current_record = NULL;
}

/* Configuration Interface */

void rr_strace_set_mode_optimized(bool strict_mode, bool skip_unmatched, int max_lookahead) {
    g_strace_state.strict_mode = strict_mode;
    g_strace_state.skip_unmatched = skip_unmatched;
    g_strace_state.max_lookahead = max_lookahead;
    
    STRACE_INFO("Optimized mode updated - strict:%s, skip:%s, lookahead:%d",
            strict_mode ? "YES" : "NO",
            skip_unmatched ? "YES" : "NO",
            max_lookahead);
}

bool rr_strace_replay_enabled_optimized(void) {
    return g_strace_state.enabled;
}

void rr_strace_get_replay_stats_optimized(uint64_t *total, uint64_t *matched, 
                                         uint64_t *skipped, uint64_t *errors) {
    if (total) *total = g_strace_state.total_syscalls;
    if (matched) *matched = g_strace_state.matched_syscalls;
    if (skipped) *skipped = g_strace_state.skipped_syscalls;
    if (errors) *errors = g_strace_state.error_syscalls;
}

/* Compatibility Wrapper Functions */
/* Provides name compatibility for rr_main.c */

bool rr_strace_replay_enabled(void) {
    return rr_strace_replay_enabled_optimized();
}

abi_long rr_replay_syscall_strace(CPUArchState *env, int num, abi_long *args) {
    return rr_replay_syscall_strace_optimized(env, num, args);
}

void rr_strace_syscall_post_hook(CPUArchState *env, int num, abi_long ret, abi_long *args) {
    rr_strace_syscall_post_hook_optimized(env, num, ret, args);
}
