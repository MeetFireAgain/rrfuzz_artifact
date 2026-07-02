/**
 * RR-Fuzz Core Framework
 * Based on design specifications.
 */

#ifndef RR_FRAMEWORK_H
#define RR_FRAMEWORK_H

#include "qemu/osdep.h"
#include "user/abitypes.h"
#include "cpu.h"

/* Include syscall number definitions */
#include "syscall_nr.h"
#include "syscall_defs.h"
#include "rr_constants.h"

/* ================= Core Data Structures ================= */

/* Forward declaration for aux data */
struct rr_aux_data;

/**
 * Syscall Record Structure - Core Data
 */
typedef struct syscall_record {
    uint32_t index;                     // Sequence number in trace
    int32_t syscall_nr;                 // Syscall number (Fixed size)
    uint64_t args[8];                   // Argument values (Fixed width for universality)
    int64_t retval;                     // Return value (Fixed width for universality)

    /* Argument data storage */
    uint8_t *arg_data[8];               // Data pointed to by arguments
    uint64_t arg_size[8];               // Size of each argument's data (Fixed width)

    /* EnvFuzz-style auxiliary data */
    struct rr_aux_data *aux_data;       // Auxiliary data linked list
    bool has_aux_data;                  // Whether it has auxiliary data

    /* Metadata */
    bool creates_fd;                    // Whether it creates a file descriptor
    bool uses_fd;                       // Whether it uses a file descriptor
    int32_t created_fd;                 // Value of created FD

    struct syscall_record *next;        // Next in linked list
} syscall_record_t;

/**
 * Fuzz command type enumeration
 */
typedef enum {
    FUZZ_CMD_NONE = 0,
    FUZZ_CMD_MUTATE_ARG,            // Mutate argument
    FUZZ_CMD_REPLACE_BUFFER,        // Replace buffer
    FUZZ_CMD_MUTATE_FLAGS,          // Mutate flags
    FUZZ_CMD_BOUNDARY_VALUE,        // Boundary value test
    
    /* Phase 1: Auxiliary data mutation commands */
    FUZZ_CMD_MUTATE_AUX_BUFFER = 5, // Mutate aux_data buffer contents
    FUZZ_CMD_FLIP_BITS = 6,         // Bit flip (randomly flip some bits)
    FUZZ_CMD_TRUNCATE = 7,          // Truncate data (reduce size)
    FUZZ_CMD_EXTEND = 8,            // Extend data (increase size)
    FUZZ_CMD_INTERESTING_VALUES = 9,// Special value injection (boundaries, magic numbers, etc.)
    FUZZ_CMD_LIGHT_MUTATION = 10,   // Lightweight mutation (minor bit flips)
    
    /* Phase 2: Precise memory overwrite command */
    FUZZ_CMD_OVERWRITE_AT_OFFSET = 11 // Overwrite data at specific offset
} fuzz_cmd_type_t;

/**
 * Fuzzing Instruction Structure (Fixed size for shared memory)
 * 
 * Supports precise memory overwriting via offset and size fields.
 */
typedef struct {
    fuzz_cmd_type_t cmd;                // Command type
    uint32_t syscall_index;             // Target syscall index
    uint32_t arg_index;                 // Target argument index
    uint32_t offset;                    // New: Offset in buffer/data
    uint32_t size;                      // New: Size of mutation data (bytes)
    uint32_t data_len;                  // Data length
    uint8_t data[4096];                 // 🔥 2026-01-22: Expanded to 4K for long payloads
} FuzzInstruction;

/**
 * Mutation instructions for a single variant
 */
typedef struct {
    uint32_t instruction_count;                         // Number of instructions for this variant
    uint64_t crash_pc;                                  // New: Faulting address if crash occurred
    FuzzInstruction instructions[RR_FUZZ_MAX_INSTRUCTIONS]; // Instruction array
} FuzzVariant;

/**
 * Shared Memory Protocol Structure
 * Includes sequence numbers to prevent concurrent read/write conflicts.
 * Supports batch variants and nested forking.
 */
typedef struct {
    uint32_t magic;                     // Magic number: 0x46555A5A ("FUZZ")
    uint32_t sequence;                  // Sequence number (incremented on each write)
    uint32_t num_variants;              // Number of variants
    uint32_t checksum;                  // Simple checksum (magic ^ sequence ^ num_variants ^ fork_point ^ depth)
    uint32_t iteration_id;              // Iteration ID
    uint32_t reserved_1;                // Reserved
    
    // ✅ New: Nested fork support
    uint32_t fork_point;                // Fork point (0=start, N=mid-point)
    uint32_t current_depth;             // Current fork depth (0=top-level, 1=nested, etc.)
    uint32_t reserved_2;                // Reserved
    
    // Single variant mode (compatible)
    FuzzInstruction instructions[RR_FUZZ_MAX_INSTRUCTIONS]; 
    
    // ✅ Batch variant mode
    FuzzVariant variants[RR_MAX_VARIANTS];            
} FuzzSharedMemory;

/* Phase 3: FuzzSharedMemory flags bits definition */
#define FUZZ_FLAG_CAPTURE_SEED  (1 << 0)  // Request new seed capture

#define FUZZ_MAGIC 0x46555A5A
#define FUZZ_MAX_INSTRUCTIONS 16        // 🔥 Consistent with shrunk instructions array
#define FUZZ_INSTRUCTION_DATA 4096      // 🔥 New 4K limit

/* ================= Run Mode Definitions ================= */

typedef enum {
    RR_MODE_DISABLED = 0,
    RR_MODE_RECORD = 1,
    RR_MODE_REPLAY = 2,
    RR_MODE_FUZZING = 3,
    RR_MODE_REPLAY_ADVANCE = 4
} rr_mode_t;

/* ================= Fork Strategy Definitions ================= */

/**
 * Fork point detection strategy
 * Controls when to trigger a fork (for fuzzing)
 */
typedef enum {
    RR_FORK_STRATEGY_STRICT = 0,      // Strict: Only I/O with ret > 0
    RR_FORK_STRATEGY_RELAXED = 1,     // Relaxed: Allow minor errors like ENOENT
    RR_FORK_STRATEGY_AGGRESSIVE = 2,  // Aggressive: Fork on any I/O syscall
    RR_FORK_STRATEGY_FALLBACK = 3     // Fallback: Force fork after N syscalls
} rr_fork_strategy_t;

/* ================= Unified Configuration System ================= */

/**
 * RR-Fuzz Configuration Structure
 * Contains only active configuration items
 */
typedef struct {
    /* Core configuration */
    bool enabled;                       // Whether RR-Fuzz is enabled
    rr_mode_t mode;                     // Running mode

    /* File path configuration */
    char *trace_file;                   // Trace file path
    char *shared_memory_name;           // Shared memory name
    char *cmd_pipe_path;                // Command pipe path
    char *status_pipe_path;             // Status pipe path
    char *config_file;                  // Configuration file path

    /* Fork Server configuration */
    bool fork_server_enabled;           // Whether Fork Server is enabled
    char *fork_syscall_name;            // Fork point syscall name (e.g., "openat", "read")
    rr_fork_strategy_t fork_strategy;   // Fork point detection strategy
    int fork_fallback_threshold;        // Force fork after N syscalls (default 20)
    char *fork_syscall_pattern;         // Fork point matching pattern (e.g. "*/input.txt")
    
    /* @deprecated - Keep for backward compatibility */
    uint32_t fork_point;                // Manual fork point (deprecated, use fork_strategy)

    /* IPC configuration */
    size_t shared_memory_size;          // Shared memory size
    int ipc_timeout;                    // IPC timeout (ms)
    
    /* Advanced configuration */
    bool use_legacy_capture;            // Use legacy capture (default false, only use aux_data)
} rr_config_t;

extern rr_config_t g_rr_config;

/**
 * Global Framework State
 */
typedef struct {
    rr_mode_t mode;
    bool enabled;

    /* Record/Replay state */
    syscall_record_t *trace_head;       // Trace head
    syscall_record_t *trace_tail;       // Trace tail
    uint32_t trace_length;              // Trace length
    uint32_t replay_index;              // Replay index

    /* IPC Communication */
    int cmd_pipe_fd;                    // Command pipe
    int status_pipe_fd;                 // Status pipe
    void *shared_memory;                // Shared memory

    /* Fork Server */
    bool fork_server_active;            // Whether Fork Server is active
    pid_t child_pid;                    // Child process PID
    bool fork_server_entered;           // Track if fork server was entered for early fork
    
    /* ✅ New: Checkpoint mechanism */
    uint32_t checkpoint_target;         // Checkpoint target index (0 means no checkpoint)
    bool at_checkpoint;                 // Whether reached checkpoint
    
    /* ✅ New: Nested fork support */
    bool is_autonomous_child;           // Whether autonomous child (auto forks at IO points)
    uint32_t current_depth;             // Current fork depth
    uint32_t forks_this_iteration;      // Forks performed in this iteration
    uint32_t current_iteration_id;      // Current iteration ID
    
    /* ✅ New: Silent replay support (true mid-point fork) */
    bool silent_replay_mode;            // true=fast replay to fork_point, no dynamic trace sent
    bool resume_from_checkpoint;        // true=direct resume of Checkpoint logic after re-entry
    
    /* ✅ New: Baseline mode support (exit after first fork point) */
    bool baseline_mode;                 // true=exit after first fork point

    /* Statistics */
    uint64_t total_syscalls;            // Total syscall count
    uint64_t deviation_count;           // Deviation count (P0: Deviation Detect)
    
    /* ✅ New: Mutation state delivery (fix for mutation detection) */
    bool last_syscall_mutated;          // Whether the last syscall was mutated

    /* ✅ New: Cleanup safety */
    pid_t root_pid;                     // PID of the root fuzzer process
} rr_framework_t;

/* ================= Global Variables ================= */

extern rr_framework_t *g_rr_framework;

/* ================= Core Functions ================= */

/* Configuration management functions */
int rr_config_init(void);
void rr_config_cleanup(void);
void rr_config_print(void);
const char *rr_config_get_mode_name(rr_mode_t mode);

/* Stabilization helpers */
void rr_stabilize_bind(CPUArchState *env, abi_long addr_ptr, abi_long addr_len);
void rr_stabilize_chdir(CPUArchState *env, abi_long path_ptr);

/* Mapping manager interface */
int rr_mapping_manager_init(size_t fd_buckets, size_t addr_buckets);
void rr_mapping_manager_cleanup(void);
int rr_fd_mapping_add(int recorded_fd, int actual_fd);
int rr_fd_mapping_get(int recorded_fd);
int rr_fd_mapping_remove(int recorded_fd);
int rr_addr_mapping_add(target_ulong recorded_addr, target_ulong actual_addr, size_t size);

/* Cache consistency */
void rr_flush_tb_cache(void);
target_ulong rr_addr_mapping_get(target_ulong recorded_addr);
int rr_addr_mapping_remove(target_ulong recorded_addr);

/* Global variables */
extern target_ulong g_pending_mmap_recorded_addr;
extern target_ulong g_pending_mmap_length;
void rr_handle_mmap_post(target_ulong recorded_addr, target_ulong actual_addr);

/* Exported for Child Trace Sync */
syscall_record_t *read_next_record(void);

/**
 * Initialize RR framework
 */
int rr_framework_init(void);

/**
 * Clean up RR framework
 */
void rr_framework_cleanup(void);

/**
 * Check if the framework is enabled
 */
static inline bool rr_framework_enabled(void) {
    return g_rr_framework && g_rr_framework->enabled;
}

/**
 * Core syscall handling function
 * This is the main function called by do_syscall
 */
abi_long rr_do_syscall(CPUArchState *env, int num,
                       abi_long *arg1, abi_long *arg2, abi_long *arg3, abi_long *arg4,
                       abi_long *arg5, abi_long *arg6, abi_long *arg7, abi_long *arg8);

/**
 * Hook function after syscall execution
 * Used for record mode
 */
void rr_syscall_post_hook(CPUArchState *env, int num, abi_long ret,
                          abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8);

/* Record disposal utility */
void rr_record_dispose(syscall_record_t *record);

/* ================= Module Function Declarations ================= */

/* Record Module */
int rr_record_syscall(CPUArchState *env, int num, const abi_long *args, abi_long ret);
int rr_start_recording(const char *trace_file);
void rr_stop_recording(void);

/* Replay Module - Hybrid Mode (Traditional binary trace) */
abi_long rr_replay_syscall(CPUArchState *env, int num, abi_long *args);
int rr_start_replay(const char *trace_file);
void rr_reset_trace_position(void);  // Reset trace file pointer (for fork server)
void rr_stop_replay(void);

/* Replay state variables - for fork_server access */
extern syscall_record_t *g_current_record;  // Currently replaying record

/* Replay state flags - for coordinating replay and post_hook */
extern __thread bool g_syscall_already_consumed;
extern __thread syscall_record_t *g_pending_post_record;

/* Replay Module - Pure Mode (EnvFuzz style) */
/* Declarations moved to rr_replay_pure.h */

/* Fork Server Module */
int rr_start_fork_server(const char *syscall_name, const char *pattern);
void rr_stop_fork_server(void);
bool rr_check_fork_point(CPUArchState *env, int syscall_nr, const char *syscall_name, const abi_long *args);
bool rr_check_auto_fork_point(int syscall_nr, const char *syscall_name, abi_long ret);
int rr_fork_server_loop(void);
void rr_reset_fork_point(void);

/* ✅ New: Nested fork support */
bool rr_should_nested_fork(int syscall_nr, const char *syscall_name, abi_long ret);
void rr_autonomous_nested_fork(int fork_index);
bool is_io_syscall(int syscall_nr);

/* ✅ New: Checkpoint Module */
int rr_save_lightweight_checkpoint(uint32_t index);
int rr_restore_lightweight_checkpoint(void);
int rr_checkpoint_fork_simple(uint32_t checkpoint_index);
bool rr_is_at_checkpoint(void);
void rr_clear_checkpoint(void);

/* IPC Module */
int rr_ipc_init(void);
void rr_ipc_cleanup(void);
int rr_ipc_send_status(int status);
int rr_ipc_send_crash_status(int status, int exit_code, int signal_number);  /* ✅ Send crash with details */
int rr_ipc_receive_command(void);

/* Fuzz Engine Module */
int rr_fuzz_apply_instructions(const FuzzInstruction *instructions, size_t count);
int rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr);
int rr_fuzz_load_from_shared_memory(void *shm_ptr, int variant_idx);
void rr_fuzz_get_stats(uint64_t *total, uint64_t *arg_mut, uint64_t *buf_mut, uint64_t *boundary);
void rr_fuzz_print_stats(void);

/* ✅ New: IO return value mutation support */
bool rr_fuzz_has_retval_override(void);
abi_long rr_fuzz_get_retval_override(void);
void rr_fuzz_clear_retval_override(void);

/* ✅ 2025-11-17: Buffer Content Mutation support (with retval override) */
void rr_fuzz_set_buffer_fill(target_ulong buf_addr, size_t size,
                               const uint8_t *pattern, size_t pattern_len);
bool rr_fuzz_has_buffer_fill(void);
size_t rr_fuzz_get_buffer_fill(target_ulong *out_addr, size_t *out_size,
                                 const uint8_t **out_pattern);
void rr_fuzz_clear_buffer_fill(void);

/* Fuzz Engine internal state - for replay module to query mutation state */
extern FuzzInstruction g_fuzz_instructions[];
extern size_t g_instruction_count;
FuzzInstruction *rr_fuzz_generate_mutations(uint32_t target_syscall, int target_arg,
                                          const uint8_t *seed_data, size_t seed_len,
                                          size_t *out_count);
void rr_fuzz_cleanup(void);

/* BB Trace Module (declared in rr_bb_trace.h, not repeated here) */

/* Coverage Module (Phase 3 - declared in rr_coverage.h, not repeated here) */

/* ━━━━ Phase 1: Pure Replay + Fuzzing Integration ━━━━ */
/**
 * Mutate data in aux_data
 * 
 * This function is used to mutate aux_data in the Pure Replay path.
 * Supports various mutation strategies: buffer replacement, bit flipping, 
 * truncation, extension, and special value injection.
 * 
 * @param env CPU environment.
 * @param record Syscall record (containing aux_data).
 * @param args Syscall arguments.
 * @param syscall_nr Syscall number.
 */
void rr_fuzz_mutate_aux_data(CPUArchState *env, syscall_record_t *record,
                              abi_long *args, int syscall_nr);

/* Strace Replay Module */
abi_long rr_replay_syscall_strace_optimized(CPUArchState *env, int num, abi_long *args);
void rr_strace_set_mode_optimized(bool strict_mode, bool skip_unmatched, int max_lookahead);
bool rr_strace_replay_enabled_optimized(void);
void rr_strace_get_replay_stats_optimized(uint64_t *total, uint64_t *matched,
                                         uint64_t *failed, uint64_t *skipped);

/* 
 * Snapshot module (Reserve API stubs)
 */
int rr_snapshot_save(uint32_t syscall_index);              
int rr_snapshot_restore(uint32_t syscall_index);           
uint32_t rr_snapshot_get_latest(void);                     
int rr_snapshot_list(uint32_t *snapshots, size_t max_count); 
bool rr_snapshot_should_save(int syscall_nr, uint32_t syscall_index); 
void rr_snapshot_auto_manage(int syscall_nr, uint32_t syscall_index); 
void rr_snapshot_cleanup(void);                            

/* Utility functions */
uint8_t *rr_capture_string(CPUArchState *env, target_ulong addr, size_t *len);
uint8_t *rr_capture_buffer(CPUArchState *env, target_ulong addr, size_t size);

/* ================= Hierarchical Debug System ================= */

/* Debug level definitions */
typedef enum {
    RR_DEBUG_OFF = 0,        // Disable all debugging
    RR_DEBUG_ERROR = 1,      // Errors only
    RR_DEBUG_WARN = 2,       // Errors and warnings
    RR_DEBUG_INFO = 3,       // Errors, warnings, and basic info
    RR_DEBUG_VERBOSE = 4,    // Detailed debug info
    RR_DEBUG_TRACE = 5       // Most detailed trace info
} rr_debug_level_t;

/* Debug configuration structure */
typedef struct {
    rr_debug_level_t level;     // Global debug level
    FILE *log_file;             // Log output file
} rr_debug_config_t;

extern rr_debug_config_t g_rr_debug;

/* Debug function declarations */
void rr_debug_init(void);
void rr_debug_set_level(rr_debug_level_t level);
void rr_debug_set_output(FILE *file);
void rr_debug_cleanup(void);
const char *rr_debug_level_name(rr_debug_level_t level);

/* Hierarchical debug macros */
#ifdef RR_DEBUG

#define RR_DEBUG_CHECK(debug_level) (g_rr_debug.level >= (debug_level))

#define RR_LOG_LEVEL(level, fmt, ...) \
    do { \
        if (RR_DEBUG_CHECK(level)) { \
            fprintf(g_rr_debug.log_file ? g_rr_debug.log_file : stderr, \
                   "[RR-%s] %s:%d " fmt "\n", \
                   rr_debug_level_name(level), __func__, __LINE__, ##__VA_ARGS__); \
            if (g_rr_debug.log_file) fflush(g_rr_debug.log_file); \
        } \
    } while(0)

#define RR_ERROR(fmt, ...)   RR_LOG_LEVEL(RR_DEBUG_ERROR, fmt, ##__VA_ARGS__)
#define RR_WARN(fmt, ...)    RR_LOG_LEVEL(RR_DEBUG_WARN, fmt, ##__VA_ARGS__)
#define RR_INFO(fmt, ...)    RR_LOG_LEVEL(RR_DEBUG_INFO, fmt, ##__VA_ARGS__)
#define RR_VERBOSE(fmt, ...) RR_LOG_LEVEL(RR_DEBUG_VERBOSE, fmt, ##__VA_ARGS__)
#define RR_TRACE(fmt, ...)   RR_LOG_LEVEL(RR_DEBUG_TRACE, fmt, ##__VA_ARGS__)

/* Conditional debug macros */
/* Simplified trace macros - all based on RR_DEBUG_LEVEL */
#define RR_SYSCALL_TRACE(fmt, ...) RR_VERBOSE("[SYSCALL] " fmt, ##__VA_ARGS__)
#define RR_FD_TRACE(fmt, ...) RR_VERBOSE("[FD] " fmt, ##__VA_ARGS__)
#define RR_MEM_TRACE(fmt, ...) RR_TRACE("[MEM] " fmt, ##__VA_ARGS__)
#define RR_IPC_TRACE(fmt, ...) RR_VERBOSE("[IPC] " fmt, ##__VA_ARGS__)
#define RR_PERF_TRACE(fmt, ...) RR_VERBOSE("[PERF] " fmt, ##__VA_ARGS__)

/* Keep backward compatibility */
#define RR_LOG(fmt, ...) RR_INFO(fmt, ##__VA_ARGS__)

#else /* !RR_DEBUG */

#define RR_ERROR(fmt, ...)   do {} while(0)
#define RR_WARN(fmt, ...)    do {} while(0)
#define RR_INFO(fmt, ...)    do {} while(0)
#define RR_VERBOSE(fmt, ...) do {} while(0)
#define RR_TRACE(fmt, ...)   do {} while(0)
#define RR_SYSCALL_TRACE(fmt, ...) do {} while(0)
#define RR_FD_TRACE(fmt, ...) do {} while(0)
#define RR_MEM_TRACE(fmt, ...) do {} while(0)
#define RR_IPC_TRACE(fmt, ...) do {} while(0)
#define RR_PERF_TRACE(fmt, ...) do {} while(0)
#define RR_LOG(fmt, ...) do {} while(0)

#endif /* RR_DEBUG */

/* ========== EnvFuzz Style: Syscall Filtering ========== */

/**
 * Determine if a syscall should be skipped (not recorded/replayed, direct execution).
 * 
 * EnvFuzz core idea: only record/replay syscalls that require determinism.
 * For memory management, process management, etc., let them execute naturally.
 */
static inline bool rr_should_skip_syscall(int syscall_nr)
{
    (void)syscall_nr;
    return false;
}

/**
 * Determine if a syscall is an output-class syscall.
 * 
 * Output syscalls must execute for real to maintain the program's I/O state.
 * In Pure Replay mode, these syscalls cannot be "replayed".
 */
static inline bool rr_is_output_syscall(int syscall_nr)
{
    switch (syscall_nr) {
        /* write/writev/send* removed: pure replay returns recorded retval to avoid
         * EBADF on replayed fds (accept() pure-replayed → no real kernel fd created).
         * Real write execution would hit EBADF and pollute coverage with error paths. */
#ifdef TARGET_NR_pwrite64
        case TARGET_NR_pwrite64:
#endif
            return true;
            
        default:
            return false;
    }
}

/* ========== Dynamic Trace API (for real-time tree visualization) ========== */
#define RR_ENABLE_DYNAMIC_TRACE 1

#ifdef RR_ENABLE_DYNAMIC_TRACE
#include "rr_dynamic_trace.h"
#endif

/* ========== ✅ 2025-11-17: IO Mutation Return Value Override Support ========== */
/* Defined in fuzzing/qemu_integration/rr_fuzz_engine.c */
extern bool g_has_retval_override;      /* Whether to override return value */
extern abi_long g_retval_override;      /* Overridden return value */

#endif /* RR_FRAMEWORK_H */