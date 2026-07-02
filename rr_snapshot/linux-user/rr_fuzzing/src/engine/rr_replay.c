/**
 * RR-Fuzz Hybrid Replay Module
 * Traditional binary trace replay functionality.
 * 
 * Responsible for:
 * - Binary trace reading and synchronization
 * - Hybrid mode system call replay (parameter application + real syscall execution)
 * - Pure Replay dispatching (for records with aux_data)
 */

#define RR_DEBUG 1

#include "rr_framework.h"
#include "rr_aux_data.h"
#include "rr_replay_pure.h"
#include "rr_constants.h"
#include "rr_dynamic_trace.h"
#include "rr_syscall_tree.h"
#include <sys/mman.h>
#include <unistd.h>

#include <sys/mman.h>
#include <stdint.h>
#include "rr_syscall_dispatch.h"

FILE *g_trace_file = NULL;  // Accessible by fork_server
syscall_record_t *g_current_record = NULL;  // Accessible by fork_server
/* Pending parent wait4 record saved during child-record skipping in silent_replay_mode.
 * When fork is suppressed, child records are skipped in the trace file until the
 * parent's wait4(retval=child_pid) is found. That wait4 record is saved here so
 * the parent application's wait4 call consumes the correct record on the next
 * rr_replay_syscall() invocation. */
static syscall_record_t *g_child_skip_pending_record = NULL;
char *g_rr_trace_path = NULL;  // Saves trace file path for child processes

/* Flag: Indicates if the current syscall has been consumed from trace and index incremented */
__thread bool g_syscall_already_consumed = false;
__thread syscall_record_t *g_pending_post_record = NULL;

/**
 * @brief Initialize Replay mode and open the trace file for replay.
 *
 * This function is the entry point for RR-Fuzz Replay/Fuzzing mode. It is responsible for:
 * 1. Opening the binary trace file (.dat format) for reading.
 * 2. Reading and validating the trace file header (magic, version).
 * 3. Reading the number of syscall records in the trace.
 * 4. Supporting the rewind mechanism when the file is already open.
 *
 * **File Header Validation**:
 * - Magic: 0x52525254 ("RRTR")
 * - Version: 1
 * - Record Count: actual number of records
 *
 * @param trace_file Trace file path. If NULL, uses the default filename "rr_trace.dat".
 *
 * @return int
 *         - 0: Initialization successful; trace file opened and validated.
 *         - -1: Initialization failed (file cannot be opened or format is invalid).
 *
 * @note This function is called in both replay and fuzzing modes.
 * @note If the trace file is already open (g_trace_file != NULL), rewind() is called
 *       instead of reopening — this supports child processes in fork-server reusing
 *       the file handle opened by the parent.
 * @note Saves the trace file path to g_rr_trace_path for child processes to reopen.
 *
 * @warning Magic mismatch or header read failure will cause initialization to fail.
 * @warning This function does not preload all trace records; they are read on demand during replay.
 *
 * @see rr_stop_replay() The corresponding stop function that closes the file.
 * @see rr_replay_syscall() Core function for reading records during replay.
 * @see rr_reset_trace_position() Reset function used by fork-server.
 * @see g_trace_file Global trace file handle.
 * @see g_rr_trace_path Saved trace path.
 */
int rr_start_replay(const char *trace_file)
{
    RR_VERBOSE("Starting replay initialization");

    if (!trace_file) {
        trace_file = "rr_trace.dat";
        RR_INFO("Using default trace file: %s", trace_file);
    }

    /* Save trace path for children to reopen */
    if (g_rr_trace_path == NULL || strcmp(g_rr_trace_path, trace_file) != 0) {
        if (g_rr_trace_path) free(g_rr_trace_path);
        g_rr_trace_path = strdup(trace_file);
    }
    
    /* If file is already open, reset the file pointer instead of reopening */
    if (g_trace_file) {
        RR_INFO("Trace file already open, rewinding to start");
        rewind(g_trace_file);
    } else {
        RR_INFO("Opening trace file for reading: %s", trace_file);
        g_trace_file = fopen(trace_file, "rb");
        if (!g_trace_file) {
            RR_ERROR("Failed to open trace file: %s (%s)", trace_file, strerror(errno));
            return -1;
        }
    }

    /* Read and validate file header */
    uint32_t magic, version;
    RR_VERBOSE("Reading trace file header");
    if (fread(&magic, sizeof(magic), 1, g_trace_file) != 1 ||
        fread(&version, sizeof(version), 1, g_trace_file) != 1) {
        RR_ERROR("Failed to read trace file header");
        fclose(g_trace_file);
        return -1;
    }

    if (magic != 0x52525254) { // "RRTR"
        RR_ERROR("Invalid trace file magic: 0x%x (expected 0x52525254)", magic);
        fclose(g_trace_file);
        return -1;
    }

    RR_VERBOSE("Trace header validated: magic=0x%x, version=%u", magic, version);
    RR_INFO("Started replay from: %s (version %u)", trace_file, version);

    /* Read record count */
    uint32_t record_count = 0;
    size_t count_read = fread(&record_count, sizeof(record_count), 1, g_trace_file);
    if (count_read != 1) {
        RR_ERROR("Failed to read record count from trace file");
        fclose(g_trace_file);
        return -1;
    }

    RR_INFO("Trace contains %u syscall records", record_count);

    return 0;
}

/**
 * Reset trace file pointer to the beginning (used by fork server)
 */
void rr_reset_trace_position(void)
{
    if (!g_trace_file) {
        RR_WARN("Cannot reset trace: file not open");
        return;
    }
    
    RR_INFO("Resetting trace file position to start");
    rewind(g_trace_file);
    
    /* Skip header (12 bytes: magic + version + count) */
    fseek(g_trace_file, 12, SEEK_SET);
}

/**
 * Stop replay
 */
void rr_stop_replay(void)
{
    if (g_trace_file) {
        RR_VERBOSE("Closing trace file");
        fclose(g_trace_file);
        g_trace_file = NULL;
        RR_INFO("Replay stopped");
    } else {
        RR_VERBOSE("Replay stop called but no trace file was open");
    }
}

/**
 * @brief Read and parse the next syscall record from the trace file.
 *
 * This function is responsible for deserializing the binary trace format and
 * reconstructing the syscall_record_t structure. It is the data source during Replay.
 *
 * **Deserialization Flow**:
 * 1. **Header**: Read index (4B) and syscall_nr (4B), manually unpacked to handle endianness.
 * 2. **Fields**: Read fixed-length fields such as args, retval, arg_sizes, fd_flags.
 * 3. **Arg Data**: Read variable-length argument data (arg_index, size, data).
 * 4. **Aux Data**: Check AUXD magic (0x41555844); if present, read the auxiliary data linked list.
 *
 * **File Format Details**:
 * - index/syscall_nr use manual packing (buffer[0-7]) to ensure cross-platform consistency.
 * - Variable-length data uses -1 as an end marker (end_marker).
 * - Aux Data is optional tail data; present only when record->has_aux_data is true.
 *
 * @return syscall_record_t*
 *         - Pointer to a newly allocated and populated record structure.
 *         - NULL: if end of file (EOF) is reached or a read error occurs.
 *
 * @note Caller is responsible for freeing the returned structure (usually managed by the replay loop).
 * @note Automatically handles record formats with or without aux_data.
 *
 * @warning Uses g_malloc internally; ensure free to avoid leaks.
 * @warning File read errors print ERROR logs but return NULL; caller must distinguish EOF and error.
 */
/* Visible for rr_fork_server.c */
syscall_record_t *read_next_record(void)
{
    /* 🔥 DEBUG: Find who calls this! */
    
    if (!g_trace_file) {
        /* Try opening trace file */RR_ERROR("READ_NEXT_RECORD: No trace file open");
        return NULL;
    }

    RR_VERBOSE("READ_NEXT_RECORD: Attempting to read next record from trace file");
    syscall_record_t *record = g_malloc0(sizeof(syscall_record_t));

    /* Read basic record - field by field to avoid alignment issues */

    // Read index (4 bytes)
    if (fread(&record->index, sizeof(uint32_t), 1, g_trace_file) != 1) {
        if (!feof(g_trace_file)) {
             RR_ERROR("READ_NEXT_RECORD: Failed to read record index (Error: %s)", strerror(errno));
        }
        g_free(record);
        return NULL;
    }

    // Read syscall_nr (4 bytes)
    if (fread(&record->syscall_nr, sizeof(int32_t), 1, g_trace_file) != 1) {
        RR_ERROR("READ_NEXT_RECORD: Failed to read syscall_nr");
        g_free(record);
        return NULL;
    }

    // Read remaining fields (Fixed width)
    uint64_t fixed_args[8];
    int64_t fixed_retval;
    uint64_t fixed_arg_sizes[8];

    if (fread(fixed_args, 8, 8, g_trace_file) != 8 ||
        fread(&fixed_retval, 8, 1, g_trace_file) != 1 ||
        fread(fixed_arg_sizes, 8, 8, g_trace_file) != 8 ||
        fread(&record->creates_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fread(&record->uses_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fread(&record->created_fd, sizeof(int32_t), 1, g_trace_file) != 1) {
        RR_ERROR("READ_NEXT_RECORD: Failed to read record fields");
        if (feof(g_trace_file)) {
            RR_ERROR("READ_NEXT_RECORD: Hit end of file");
        }
        if (ferror(g_trace_file)) {
            RR_ERROR("READ_NEXT_RECORD: File read error");
        }
        g_free(record);
        return NULL;
    }

    /* Convert fixed-width back to native fields - Handle Little Endian conversion */
    for (int i = 0; i < 8; i++) record->args[i] = (abi_long)le64_to_cpu(fixed_args[i]);
    record->retval = (abi_long)le64_to_cpu((uint64_t)fixed_retval);
    for (int i = 0; i < 8; i++) record->arg_size[i] = (size_t)le64_to_cpu(fixed_arg_sizes[i]);

    uint32_t le_created_fd;
    memcpy(&le_created_fd, &record->created_fd, sizeof(uint32_t));
    record->created_fd = (int32_t)le32_to_cpu(le_created_fd);


    RR_VERBOSE("READ_NEXT_RECORD: Successfully read record fields");
    RR_VERBOSE("READ_NEXT_RECORD: Record data - index=%u, syscall=%d, ret=%ld",
               record->index, record->syscall_nr, (long)record->retval);

    /* Read parameter data */
    int32_t le_arg_index;
    while (fread(&le_arg_index, sizeof(int32_t), 1, g_trace_file) == 1) {
        int32_t arg_index = (int32_t)le32_to_cpu((uint32_t)le_arg_index);
        if (arg_index == -1) { // End marker
            break;
        }


        if (arg_index >= 0 && arg_index < RR_MAX_SYSCALL_ARGS) {
            uint64_t le_size;
            if (fread(&le_size, sizeof(uint64_t), 1, g_trace_file) == 1) {
                uint64_t size = le64_to_cpu(le_size);
                if (size > 0 && size <= RR_MAX_BUFFER_TOTAL) {
                    record->arg_data[arg_index] = g_malloc(size);
                    if (fread(record->arg_data[arg_index], 1, size, g_trace_file) == size) {
                        record->arg_size[arg_index] = size;
                    } else {
                        g_free(record->arg_data[arg_index]);
                        record->arg_data[arg_index] = NULL;
                        record->arg_size[arg_index] = 0;
                    }
                }
            }
        }

    }

    /* Read aux_data if available */
    uint32_t le_aux_marker = 0;
    RR_VERBOSE("READ_NEXT_RECORD: About to read aux_marker at file pos %ld", ftell(g_trace_file));
    if (fread(&le_aux_marker, sizeof(uint32_t), 1, g_trace_file) == 1) {
        uint32_t aux_marker = le32_to_cpu(le_aux_marker);
        RR_VERBOSE("READ_NEXT_RECORD: Read aux_marker = 0x%08x", aux_marker);
        if (aux_marker == 0x41555844) { // "AUXD" magic
            RR_VERBOSE("READ_NEXT_RECORD: Found AUXD magic, reading aux_data");
            /* Read aux_data count */
            uint32_t le_aux_count = 0;
            if (fread(&le_aux_count, sizeof(uint32_t), 1, g_trace_file) == 1) {
                uint32_t aux_count = le32_to_cpu(le_aux_count);
                RR_VERBOSE("READ_NEXT_RECORD: aux_count = %u", aux_count);
                record->has_aux_data = true;
                
                /* Read each aux_data exit */
                for (uint32_t i = 0; i < aux_count; i++) {
                    uint8_t kind, arg_mask;
                    uint32_t le_size;
                    
                    if (fread(&kind, sizeof(uint8_t), 1, g_trace_file) != 1 ||
                        fread(&arg_mask, sizeof(uint8_t), 1, g_trace_file) != 1 ||
                        fread(&le_size, sizeof(uint32_t), 1, g_trace_file) != 1) {
                        RR_ERROR("READ_NEXT_RECORD: Failed to read aux_data header");
                        break;
                    }
                    uint32_t size = le32_to_cpu(le_size);

                    
                    /* Read data */
                    uint8_t *data = g_malloc(size);
                    if (fread(data, size, 1, g_trace_file) == 1) {
                        rr_aux_data_t *aux = rr_aux_create((rr_aux_kind_t)kind, arg_mask, data, size);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            RR_VERBOSE("READ_NEXT_RECORD: Read aux_data kind=%d, arg=%d, size=%u",
                                       kind, arg_mask, size);
                        }
                    }
                    g_free(data);
                }
            }
        } else if (aux_marker != 0) {
            /* If it's not AUXD and not 0, it might be a desync or a legacy trace. 
             * But for version 1, it should be one of them. 
             * We do NOT seek back here if we expect a marker. 
             */
            RR_VERBOSE("READ_NEXT_RECORD: Unexpected marker 0x%08x at pos %ld", aux_marker, ftell(g_trace_file));
        }
    } else {
        if (!feof(g_trace_file)) {
            RR_ERROR("READ_NEXT_RECORD: Failed to read aux_marker at pos %ld", ftell(g_trace_file));
        }
    }

    return record;
}

/**
 * Apply FD mapping
 */
static void apply_fd_mapping(abi_long *args, int syscall_nr)
{
    switch (syscall_nr) {
        case TARGET_NR_read:
        case TARGET_NR_write:
        case TARGET_NR_close:
#ifdef TARGET_NR_lseek
        case TARGET_NR_lseek:
#endif
#ifdef TARGET_NR_fstat
        case TARGET_NR_fstat:
#endif
            /* First argument is FD */
            if (args[0] >= 0) {
                int mapped_fd = rr_fd_mapping_get((int)args[0]);
                args[0] = mapped_fd;
            }
            break;

#ifdef TARGET_NR_dup2
        case TARGET_NR_dup2:
#endif
            /* Both arguments are FDs */
            for (int i = 0; i < 2; i++) {
                if (args[i] >= 0) {
                    int mapped_fd = rr_fd_mapping_get((int)args[i]);
                    args[i] = mapped_fd;
                }
            }
            break;

#ifdef TARGET_NR_mmap
        case TARGET_NR_mmap:
#endif
#ifdef TARGET_NR_mmap2
        case TARGET_NR_mmap2:
#endif
            /* 5th argument of mmap (args[4]) is the FD */
            if (args[4] >= 0) {  /* Not anonymous mapping */
                int mapped_fd = rr_fd_mapping_get((int)args[4]);
                if (mapped_fd != (int)args[4]) {
                    RR_VERBOSE("FD_MAPPING: mmap fd %d -> %d", (int)args[4], mapped_fd);
                }
                args[4] = mapped_fd;
            }
            break;

        // More syscall FD mapping handling can be added here
        default:
            break;
    }
}

/* 
 * NOTE: update_fd_mapping() has been removed.
 * FD mapping is handled by apply_fd_mapping().
 * Pure Replay functionality moved to rr_replay_pure.c. 
 */

/**
 * @brief Replay a single syscall - Hybrid/Pure automatic dispatch.
 * 
 * Core function in Replay/Fuzzing mode, automatically selecting strategy based on trace data:
 * - **Pure Replay**: Fully restored in userspace via aux_data; no real syscall executed (except brk/mmap).
 * - **Hybrid Replay**: Executed as a real syscall with FD/address mappings applied.
 * 
 * **Workflow**:
 * 1. Read next record from trace and synchronize (syscall_nr match).
 * 2. Detect and exit silent replay mode (if fork point reached).
 * 3. Determine if Pure Replay is possible.
 *    - Yes: Call rr_replay_syscall_pure(), return recorded retval.
 *    - No: Hybrid path, apply mappings, return -1 to let QEMU execute real syscall.
 * 4. Fuzzing mode: apply mutations (fuzz_mutate_syscall).
 * 
 * **Trace Synchronization**:
 * - Automatically skips trace records if current syscall doesn't match until a match is found.
 * - Provides fault tolerance allowing minor differences between record and replay.
 * 
 * **Special Cases**:
 * - Output syscalls (write/writev): Forced Hybrid to maintain I/O state.
 * - mmap/brk: Forced Hybrid because QEMU must manage memory mappings.
 *
 * @param env CPU architecture state pointer (for guest memory R/W).
 * @param num Current syscall number.
 * @param args Syscall argument array (8 arguments); may be modified for Pure Replay.
 * 
 * @return abi_long
 *         - Not -1: Pure Replay successful; returns recorded retval to QEMU.
 *         - -1: Hybrid Replay; let QEMU execute real syscall (args may be modified).
 * 
 * @note Automatically increments g_rr_framework->replay_index.
 * @note Supports Dynamic Trace (RR_ENABLE_DYNAMIC_TRACE) for visualization.
 * @note Maintains global state: g_current_record, g_pending_post_record.
 * 
 * @warning Complex state management: g_syscall_already_consumed, g_pending_mmap_recorded_addr, etc.
 *          Must be carefully maintained to avoid double consumption or missed records.
 * @warning Fuzzing mutation modifies the args array, affecting subsequent execution.
 * 
 * @see rr_start_replay() Must call this function to open trace file first
 * @see rr_replay_syscall_pure() Implementation of Pure Replay
 * @see read_next_record() Read record from trace file
 * @see apply_fd_mapping() Core logic for applying FD mapping
 * @see rr_fuzz_mutate_syscall() Mutation application in Fuzzing mode
 */
abi_long rr_replay_syscall(CPUArchState *env, int num, abi_long *args)
{
    fprintf(stderr, "[DEBUG-REPLAY-ENTRY] PID=%d, NR=%d\n", getpid(), num);
    RR_VERBOSE("REPLAY_SYSCALL: Entry for syscall %d", num);
    RR_VERBOSE("REPLAY_SYSCALL: g_rr_framework=%p", g_rr_framework);
    RR_VERBOSE("REPLAY_SYSCALL: g_trace_file=%p", g_trace_file);

    /* Reset flags */
    g_syscall_already_consumed = false;
    if (g_rr_framework) g_rr_framework->last_syscall_mutated = false;

    if (!g_rr_framework) {
        fprintf(stderr, "[DEBUG-REPLAY] PID=%d ERROR: g_rr_framework is NULL\n", getpid());
        return -1;
    }

    if (!g_trace_file) {
        RR_VERBOSE("REPLAY_SYSCALL: g_trace_file is NULL, returning -1");
        RR_ERROR("REPLAY_SYSCALL: g_trace_file is NULL");
        return -1;
    }

    RR_VERBOSE("REPLAY_SYSCALL: Called for syscall %d, replay_index=%u", num, g_rr_framework->replay_index);
    RR_VERBOSE("REPLAY_SYSCALL: g_trace_file=%p, g_current_record=%p", g_trace_file, g_current_record);

    /* No skip check: always attempt to read from trace to ensure consistency */

    /* Check if fork_point is reached to disable silent mode and re-enter loop */
    if (g_rr_framework->silent_replay_mode) {
        uint32_t target_fork_point = g_rr_framework->checkpoint_target;
        if (g_rr_framework->replay_index >= target_fork_point) {
            g_rr_framework->silent_replay_mode = false;
            RR_INFO("✅ [Hybrid] Reached fork_point[%u], re-entering fork server loop", target_fork_point);
            
            /* 🔥 ARCH-FIX: Re-enter fork server loop to perform the checkpoint-fork */
            /* This is required because the parent process returned to ADVANCE to this point.
             * This call will block in the parent until a command is received (usually 'C' logic if resume_from_checkpoint is true).
             * Children will return 1 from this call and continue guest execution.
             */
            rr_fork_server_loop();
        }
    }
    
    /* Maintain global index synchronization - core requirement from design.md */
    RR_VERBOSE("REPLAY_SYSCALL: replay_index=%u, g_current_record=%p", g_rr_framework->replay_index, g_current_record);
    if (g_rr_framework->replay_index == 0 || !g_current_record) {
        if (g_child_skip_pending_record) {
            /* Inject the parent wait4 record saved during child-record skipping. */
            g_current_record = g_child_skip_pending_record;
            g_child_skip_pending_record = NULL;
            fprintf(stderr, "[DEBUG-REPLAY] PID=%d injecting saved parent-wait4 record idx=%u nr=%d\n",
                    getpid(), g_current_record->index, g_current_record->syscall_nr);
        } else {
        fprintf(stderr, "[DEBUG-REPLAY] PID=%d reading record for index %u\n", getpid(), g_rr_framework->replay_index);
        g_current_record = read_next_record();
        
        if (!g_current_record) {
            fprintf(stderr, "[DEBUG-REPLAY] PID=%d read_next_record returned NULL\n", getpid());
            /* EnvFuzz style: If record is not found, don't crash, execute for real */
            RR_WARN("REPLAY_SYSCALL: End of trace at index %u for syscall %d, executing directly", 
                    g_rr_framework->replay_index, num);
            
            /* ✅ Fix: Real execution also needs to send dynamic trace! */
            // extern bool g_dynamic_trace_enabled;
            // extern int g_dynamic_trace_pipe_fd;
            RR_INFO("🔍 About to send dynamic trace: silent=%d, enabled=%d, pipe_fd=%d",
                    g_rr_framework->silent_replay_mode, g_dynamic_trace_enabled, g_dynamic_trace_pipe_fd);
            if (!g_rr_framework->silent_replay_mode) {
                uint64_t args_copy[8];
                for (int i = 0; i < 8; i++) {
                    args_copy[i] = ((uint64_t*)args)[i];
                }
                rr_dynamic_trace_syscall_enter(env, num, args_copy, 
                                                g_rr_framework->replay_index, false);
                RR_INFO("✅ Sent dynamic trace for syscall %d at index %u",
                        num, g_rr_framework->replay_index);
            }
            
            /* ✅ Increment replay_index (even for real execution) */
            g_rr_framework->replay_index++;
            
            /* 🔥 THE FINAL FIX: In fuzzing mode, never free-wheel into native execution after trace EOF. */
            /* Native execution of network code without a recorded environment always leads to hangs. */
            if (g_rr_framework->mode == RR_MODE_FUZZING) {
                if (g_rr_debug.level >= RR_DEBUG_INFO) {
                    fprintf(stderr, "[FUZZ-REPLAY] Trace exhausted at syscall %d, exiting child %d cleanly.\n", num, getpid());
                }
                exit(0);
            }

            
            return -1;  /* Execute syscall directly */
        }
        RR_VERBOSE("REPLAY_SYSCALL: Got record index=%u, syscall=%d, ret=%d",
                g_current_record->index, g_current_record->syscall_nr, (int)g_current_record->retval);
        RR_VERBOSE("REPLAY_SYSCALL: Got record index=%u, syscall=%d, ret=%d",
                   g_current_record->index, g_current_record->syscall_nr, (int)g_current_record->retval);
        } /* end else (no pending record) */
    }

    /* 🔥 GAP FIX: Handle unrecorded syscalls (Gap in trace) */
    /* If the next record index is in the future, the current syscall was not recorded. */
    /* We should execute it natively and increment our counter. */
    if (g_current_record && g_current_record->index > g_rr_framework->replay_index) {
        RR_VERBOSE("REPLAY: Unrecorded syscall %d (Current Index %u < Next Record Index %u). Executing natively.", 
                   num, g_rr_framework->replay_index, g_current_record->index);
        
        g_rr_framework->replay_index++;
        return -1; /* Execute natively */
    }

    /* Smart synchronization - if syscall doesn't match, continue reading until a match is found.
     * NOTE: Disabled in silent_replay_mode (parent advancing to fork_point): HYBRID divergence
     * causes NR mismatches that would exhaust the trace before reaching fork_point.
     * The post-sync catch-all below handles the mismatch case for silent_replay_mode. */
    while (!g_rr_framework->silent_replay_mode &&
           g_current_record && g_current_record->syscall_nr != num) {
        RR_VERBOSE("⚠️ [REPLAY-SYNC] MISMATCH at index %u: recorded_nr=%d (%s), actual_nr=%d (%s). Skipping record.",
                g_current_record->index,
                g_current_record->syscall_nr, rr_get_syscall_name_fast(g_current_record->syscall_nr),
                num, rr_get_syscall_name_fast(num));

        /* Dynamic trace: Record skipped syscall (for tree integrity) */
#ifdef RR_ENABLE_DYNAMIC_TRACE
        uint64_t dummy_args[8] = {0};
        rr_dynamic_trace_syscall_enter(env, g_current_record->syscall_nr, dummy_args, 
                                         g_rr_framework->replay_index, 0);
        rr_dynamic_trace_syscall_exit(env, g_current_record->syscall_nr, dummy_args,
                                        g_current_record->retval, g_rr_framework->replay_index, 0);
#endif

        /* Clear current record (using unified dispose function) */
        rr_record_dispose(g_current_record);
        
        /* 🔥 Key Fix: Increment replay_index even when skipping records */
        g_rr_framework->replay_index++;

        /* Read next record */
        g_current_record = read_next_record();
        if (!g_current_record) {
             if (g_rr_framework->mode == RR_MODE_FUZZING) {
                 if (g_rr_debug.level >= RR_DEBUG_INFO) {
                     fprintf(stderr, "[FUZZ-REPLAY] Trace exhausted during sync at syscall %d, exiting child %d cleanly.\n", num, getpid());
                 }
                 exit(0);
             }
             
             RR_WARN("REPLAY_SYSCALL: End of Trace reached (EOF) during sync. Switching to free execution.");
             break;
        }

        RR_VERBOSE("REPLAY_SYSCALL: Trying next record index=%u, syscall=%d",
                   g_current_record->index, g_current_record->syscall_nr);
    }

    if (!g_current_record) {
        RR_WARN("REPLAY_SYSCALL: Trace exhausted while searching for syscall %d, switching to native execution", num);
        
        /* ✅ Fix: Real execution also needs to send dynamic trace! */
        if (!g_rr_framework->silent_replay_mode) {
            uint64_t args_copy[8];
            for (int i = 0; i < 8; i++) {
                args_copy[i] = ((uint64_t*)args)[i];
            }
#ifdef RR_ENABLE_DYNAMIC_TRACE
            rr_dynamic_trace_syscall_enter(env, num, args_copy, 
                                            g_rr_framework->replay_index, false);
#endif
        }
        
        g_rr_framework->replay_index++;
        
        /* 🔥 FUZZING GUARD: Exit cleanly instead of blocking natively on network IO */
        if (g_rr_framework->mode == RR_MODE_FUZZING) {
            bool is_blocking_io = false;
#ifdef TARGET_NR_recv
            if (num == TARGET_NR_recv) is_blocking_io = true;
#endif
#ifdef TARGET_NR_recvfrom
            if (num == TARGET_NR_recvfrom) is_blocking_io = true;
#endif
#ifdef TARGET_NR_recvmsg
            if (num == TARGET_NR_recvmsg) is_blocking_io = true;
#endif
#ifdef TARGET_NR_accept
            if (num == TARGET_NR_accept) is_blocking_io = true;
#endif
#ifdef TARGET_NR_accept4
            if (num == TARGET_NR_accept4) is_blocking_io = true;
#endif
#ifdef TARGET_NR_epoll_wait
            if (num == TARGET_NR_epoll_wait) is_blocking_io = true;
#endif
#ifdef TARGET_NR_epoll_pwait
            if (num == TARGET_NR_epoll_pwait) is_blocking_io = true;
#endif
#ifdef TARGET_NR_select
            if (num == TARGET_NR_select) is_blocking_io = true;
#endif
#ifdef TARGET_NR__newselect
            if (num == TARGET_NR__newselect) is_blocking_io = true;
#endif
#ifdef TARGET_NR_pselect6
            if (num == TARGET_NR_pselect6) is_blocking_io = true;
#endif
#ifdef TARGET_NR_socketcall
            if (num == TARGET_NR_socketcall) {
                int call = (int)args[0];
                if (call == TARGET_SYS_ACCEPT || call == TARGET_SYS_ACCEPT4 || 
                    call == TARGET_SYS_RECV || call == TARGET_SYS_RECVFROM || 
                    call == TARGET_SYS_RECVMSG) {
                    is_blocking_io = true;
                }
            }
#endif
            if (is_blocking_io) {
                fprintf(stderr, "[FUZZ-REPLAY] Trace sync exhausted at blocking IO syscall %d, exiting cleanly.\n", num);
                exit(0);
            }
        }
        
        return -1;
    }

    if (g_current_record->syscall_nr != num) {
        if (g_rr_framework->silent_replay_mode) {
            /* In silent_replay_mode, NR mismatch after disabled sync loop is expected
             * due to HYBRID divergence. Consume record in order, return recorded retval. */
            RR_VERBOSE("REPLAY: silent_replay_mode NR-mismatch at idx=%u: recorded=%d actual=%d — consuming in order",
                       g_current_record->index, g_current_record->syscall_nr, num);
            /* Fall through to abi_long ret declaration and post-sync catch-all below */
        } else {
            RR_ERROR("REPLAY_SYSCALL: Could not find matching syscall for %d", num);
            return -1;
        }
    }

    RR_VERBOSE("REPLAY_SYSCALL: FOUND MATCH - syscall=%d at record index=%u",
            num, g_current_record->index);
    RR_VERBOSE("REPLAY_SYSCALL: Found matching syscall %d at record index %u",
               num, g_current_record->index);

    /* Check if mutation is applied */
    int has_mutation = 0;
    if (g_rr_framework->mode == RR_MODE_FUZZING) {
        /* Pre-check for mutations (for setting is_fuzzed flag) */
        for (size_t i = 0; i < g_instruction_count; i++) {
            if (g_fuzz_instructions[i].syscall_index == g_current_record->index) {
                has_mutation = 1;
                break;
            }
        }
    }

    /* Dynamic trace: Syscall enter (binary replay path) */
#ifdef RR_ENABLE_DYNAMIC_TRACE
    rr_dynamic_trace_syscall_enter(env, num, (uint64_t*)args, 
                                     g_rr_framework->replay_index, has_mutation);
#endif

    abi_long ret = g_current_record->retval;

    /* ── SILENT-REPLAY CATCH-ALL ──────────────────────────────────────────────
     * When parent is advancing to fork_point (silent_replay_mode=true), HYBRID
     * divergence can cause the actual syscall NR to differ from the recorded NR.
     * The sync loop above skips records looking for a matching NR and can exhaust
     * the trace (→ exit(0)) before we reach fork_point.
     *
     * After the sync loop, g_current_record may now point to a record with a
     * different NR than `num` only if we exited the loop early. But the real
     * problem is when the sync loop SKIPS records: we handle that here by
     * detecting that the MATCHED record has a different NR (loop didn't match
     * anything useful). Actually the sync loop already advanced past the mismatch.
     *
     * Simpler guard: if we are in silent_replay_mode AND g_current_record->syscall_nr
     * still doesn't match `num` after the sync loop, we force-consume the record
     * and return the recorded retval to keep the parent advancing.
     * ────────────────────────────────────────────────────────────────────────── */
    if (g_rr_framework->silent_replay_mode && g_current_record &&
        g_current_record->syscall_nr != num) {
        RR_VERBOSE("REPLAY: silent_replay_mode NR-mismatch at idx=%u: recorded=%d actual=%d — returning 0 (safe default)",
                   g_current_record->index, g_current_record->syscall_nr, num);
        /* Return 0 (universal "success/no-data") for NR-mismatched syscalls in
         * silent_replay_mode. Using the recorded retval of the WRONG syscall is unsafe:
         * a large retval (e.g., 131074 from fcntl) returned for accept() would be treated
         * as a huge fd number, causing FD_SET overflow → stack corruption → SIGSEGV.
         * 0 is safe: fstat returns 0=success, close/setsockopt return 0=success,
         * read returns 0=EOF (application closes connection cleanly), etc.
         * Syscalls that return fds (open/accept/socket) also get 0 (fd=0=stdin-reuse),
         * which may cause cert loading to fail but httpd continues and reaches accept/read. */
        ret = 0;
        goto replay_success;
    }

    /* Special Case 1: Output Syscalls */
    /* Output syscalls must be executed to maintain I/O state, but record must be consumed */
    /* Mutations are applied before executing the real syscall */
    if (rr_is_output_syscall(num)) {
        RR_INFO("REPLAY_SYSCALL: Output syscall %d (Hybrid Replay), consuming record and executing directly", num);
        
        /* Apply mutation before executing output syscall */
        if (g_rr_framework->mode == RR_MODE_FUZZING) {
            uint32_t syscall_index = g_current_record->index;
            RR_INFO("🎯 FUZZING MODE: Applying mutations for OUTPUT syscall %d at index %u", num, syscall_index);
            int m_res = rr_fuzz_mutate_syscall(env, syscall_index, args, num);
            if (m_res > 0) g_rr_framework->last_syscall_mutated = true;
            
            /* 🔥 FIX: Retval override for output syscalls should skip real execution */
            /* If the fuzzer overrides the retval for writev, we skip native execution 
               and return the mutated value, instead of letting native execution clear it but 
               keeping the flag true, which corrupted the next syscall (e.g., mprotect) */
            if (rr_fuzz_has_retval_override()) {
                goto replay_success;
            }
        }
        
        /* Clear current record */
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
            if (g_current_record->arg_data[i]) {
                g_free(g_current_record->arg_data[i]);
            }
        }
        if (g_current_record->aux_data) {
            rr_aux_free(g_current_record->aux_data);
        }
        g_free(g_current_record);
        g_current_record = NULL;
        
        /* Advance index */
        g_rr_framework->replay_index++;
        
        /* Set flag to prevent post_hook from double processing */
        g_syscall_already_consumed = true;
        
        return -1; /* Execute real syscall */
    }

    /* Special Case 2: Memory Management Syscalls */
    /* mmap and others require real allocation, but force recorded address */
    bool is_mmap = false;
#ifdef TARGET_NR_mmap
    if (num == TARGET_NR_mmap) is_mmap = true;
#endif
#ifdef TARGET_NR_mmap2
    if (num == TARGET_NR_mmap2) is_mmap = true;
#endif
    if (is_mmap && g_current_record && g_current_record->has_aux_data) {
        rr_aux_data_t *aux = rr_aux_find(g_current_record->aux_data, 0);
        if (aux && aux->data && aux->size == sizeof(rr_aux_mmap_info_t)) {
            rr_aux_mmap_info_t info;
            memcpy(&info, aux->data, sizeof(info));

            RR_VERBOSE("REPLAY_SYSCALL: Hybrid mmap referencing recorded addr=0x%lx len=%lu",
                       (unsigned long)info.addr, (unsigned long)info.length);

            /* Record original address and length, let post_hook establish mapping */
            g_pending_mmap_recorded_addr = (target_ulong)info.addr;
            g_pending_mmap_length = (target_ulong)info.length;

            /* Use current parameters (do not force MAP_FIXED) */
            args[2] = (abi_long)info.prot;
            args[3] = (abi_long)info.flags;
            args[4] = (abi_long)info.fd;
            args[5] = (abi_long)info.offset;
        }
    }

    /* ========== Path Bifurcation: Pure vs Hybrid ========== */
    
    /* 🎯 CRITICAL FIX: Force Hybrid Replay for I/O syscalls in FUZZING/REPLAY mode */
    if (g_rr_framework->mode == RR_MODE_FUZZING || g_rr_framework->mode == RR_MODE_REPLAY) {
        bool is_io = (
#ifdef TARGET_NR_read
//                      num == TARGET_NR_read ||
#endif
#ifdef TARGET_NR_write
//                    num == TARGET_NR_write ||  // REMOVED: write goes pure replay to avoid EBADF coverage noise
#endif
#ifdef TARGET_NR_open
                      num == TARGET_NR_open ||
#endif
#ifdef TARGET_NR_openat
                      num == TARGET_NR_openat ||
#endif
#ifdef TARGET_NR_close
                      num == TARGET_NR_close ||
#endif
#ifdef TARGET_NR_lseek
                      num == TARGET_NR_lseek ||
#endif
#ifdef TARGET_NR_llseek
                      num == TARGET_NR_llseek ||
#endif
#ifdef TARGET_NR_fstat
                      num == TARGET_NR_fstat ||
#endif
#ifdef TARGET_NR_newfstatat
                      num == TARGET_NR_newfstatat ||
#endif
#ifdef TARGET_NR_pread64
                      num == TARGET_NR_pread64 ||
#endif
#ifdef TARGET_NR_mmap
                      num == TARGET_NR_mmap ||
#endif
#ifdef TARGET_NR_mmap2
                      num == TARGET_NR_mmap2 ||
#endif
                      /* brk must be HYBRID: pure replay returns wrong address without
                       * adjusting QEMU guest heap, causing SIGSEGV when accessing newly
                       * "allocated" memory. HYBRID lets QEMU execute real brk and return
                       * the actual new heap address. */
#ifdef TARGET_NR_brk
                      num == TARGET_NR_brk ||
#endif
                      0);
        if (is_io) {
            goto try_hybrid;
        }
    }

    /* In silent_replay_mode, force HYBRID for read-like syscalls that have aux_data.
     * Pure replay would write recorded data to the application's buffer using the
     * application's CURRENT arg pointers. After fork suppression and NR-mismatch
     * catch-alls, the parent's buffer pointers may be invalid → SIGSEGV in pure replay.
     * HYBRID executes the real read; if the fd is invalid it returns -EBADF safely. */
    if (g_rr_framework->silent_replay_mode && g_current_record->has_aux_data) {
#ifdef TARGET_NR_read
        if (num == TARGET_NR_read) { goto try_hybrid; }
#endif
#ifdef TARGET_NR_readv
        if (num == TARGET_NR_readv) { goto try_hybrid; }
#endif
#ifdef TARGET_NR_pread64
        if (num == TARGET_NR_pread64) { goto try_hybrid; }
#endif
    }

    if (g_current_record->has_aux_data) {
        /* Path 1: Pure Replay */
        RR_VERBOSE("REPLAY: Pure replay path for syscall %d (has aux_data)", num);
        
        /* 
         * Strategy: Restore aux_data to buffer first, then apply mutation 
         * to allow mutations to overwrite existing data.
         */
        
        /* 🎯 CRITICAL FIX: Force Hybrid Replay for I/O syscalls in FUZZING mode
         * to ensure target code actually executes and provides real coverage.
         * 
         * Pure Replay would skip target code execution by restoring aux_data directly.
         * Hybrid Replay forces QEMU to execute real syscall, which requires running
         * target code to reach the syscall point.
         * 
         * Note: Check both RR_MODE_FUZZING and RR_MODE_REPLAY because baseline children
         * are in REPLAY mode (rr_fork_server.c:780) while batch children are in FUZZING mode.
         */
        if (g_rr_framework->mode == RR_MODE_FUZZING || g_rr_framework->mode == RR_MODE_REPLAY) {
            bool is_io_syscall = false;
            
#ifdef TARGET_NR_read
//            if (num == TARGET_NR_read) is_io_syscall = true;
#endif
#ifdef TARGET_NR_write
//            if (num == TARGET_NR_write) is_io_syscall = true;  // REMOVED: write goes pure replay to avoid EBADF coverage noise
#endif
#ifdef TARGET_NR_open
            if (num == TARGET_NR_open) is_io_syscall = true;
#endif
#ifdef TARGET_NR_openat
            if (num == TARGET_NR_openat) is_io_syscall = true;
#endif
#ifdef TARGET_NR_close
            if (num == TARGET_NR_close) is_io_syscall = true;
#endif
#ifdef TARGET_NR_lseek
            if (num == TARGET_NR_lseek) is_io_syscall = true;
#endif
#if defined(TARGET_NR_fstat)
            if (num == TARGET_NR_fstat) is_io_syscall = true;
#endif
#if defined(TARGET_NR_newfstatat)
            if (num == TARGET_NR_newfstatat) is_io_syscall = true;
#endif
            
            if (is_io_syscall) {
                RR_INFO("🎯 HYBRID-FORCE: Forcing Hybrid Replay for I/O syscall %d (mode=%d) to execute target code", 
                        num, g_rr_framework->mode);
                goto try_hybrid;
            }
        }
        
        /* Step 1: Restore aux_data to buffer first (if any) */
        ret = rr_replay_syscall_pure(env, num, args, g_current_record);
        
        if (ret == -1) {
            /* In FUZZING mode: bypass hybrid for syscalls that operate on virtual fds.
             * After accept() is pure-replayed (no real kernel fd created), any subsequent
             * syscall on that fd (flock, fcntl, select, etc.) would return EBADF in hybrid
             * mode, driving the binary into error-handling paths and skipping the mutation
             * surface (e.g. HTTP read). Return recorded retval directly instead. */
            if (g_rr_framework->mode == RR_MODE_FUZZING) {
#ifdef TARGET_NR_flock
                if (num == TARGET_NR_flock) {
                    ret = g_current_record->retval;
                    RR_VERBOSE("REPLAY: FUZZING flock() bypass, retval=%d", (int)ret);
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR_fcntl
                if (num == TARGET_NR_fcntl) {
                    ret = g_current_record->retval;
                    RR_VERBOSE("REPLAY: FUZZING fcntl() bypass, retval=%d", (int)ret);
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR_fcntl64
                if (num == TARGET_NR_fcntl64) {
                    ret = g_current_record->retval;
                    RR_VERBOSE("REPLAY: FUZZING fcntl64() bypass, retval=%d", (int)ret);
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR_select
                if (num == TARGET_NR_select) {
                    ret = g_current_record->retval;
                    RR_VERBOSE("REPLAY: FUZZING select() bypass, retval=%d", (int)ret);
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR__newselect
                if (num == TARGET_NR__newselect) {
                    ret = g_current_record->retval;
                    RR_VERBOSE("REPLAY: FUZZING _newselect() bypass, retval=%d", (int)ret);
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR_poll
                if (num == TARGET_NR_poll) {
                    ret = g_current_record->retval;
                    RR_VERBOSE("REPLAY: FUZZING poll() bypass, retval=%d", (int)ret);
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR_ppoll
                if (num == TARGET_NR_ppoll) {
                    ret = g_current_record->retval;
                    RR_VERBOSE("REPLAY: FUZZING ppoll() bypass, retval=%d", (int)ret);
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR_socket
                if (num == TARGET_NR_socket) {
                    ret = g_current_record->retval;
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR_bind
                if (num == TARGET_NR_bind) {
                    ret = g_current_record->retval;
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR_listen
                if (num == TARGET_NR_listen) {
                    ret = g_current_record->retval;
                    goto replay_success;
                }
#endif
#ifdef TARGET_NR_sendmsg
                if (num == TARGET_NR_sendmsg) {
                    ret = g_current_record->retval;
                    goto replay_success;
                }
#endif
            }
            /* Pure replay failed, use hybrid mode */
            RR_VERBOSE("REPLAY: Pure replay not supported for syscall %d, using hybrid", num);
            goto try_hybrid;
        }
        
        /* Apply mutation to args and restored guest memory in fuzzing mode */
        if (g_rr_framework->mode == RR_MODE_FUZZING) {
            uint32_t syscall_index = g_current_record->index;
            RR_INFO("🎯 FUZZING: Applying mutations AFTER aux_data restore for syscall %d at index %u",
                    num, syscall_index);

            /* Step 2a: Apply instruction-based mutations (REPLACE_BUFFER, FLIP_BITS, MUTATE_ARG etc.) */
            int mutation_result = rr_fuzz_mutate_syscall(env, syscall_index, args, num);

            if (mutation_result > 0) {
                RR_INFO("🎯 FUZZING: Buffer mutation applied, overwrote aux_data");
                g_rr_framework->last_syscall_mutated = true;
            }

            /* Step 2b: Apply aux_data mutations (MUTATE_AUX_BUFFER, INTERESTING_VALUES etc.)
             * These modify aux->data in the C struct (format strings, cmd injection, path traversal...) */
            rr_fuzz_mutate_aux_data(env, g_current_record, args, num);

            /* Step 2c: Write mutated aux_data back to guest memory */
            abi_long reapply_ret = rr_replay_syscall_pure_reapply(env, num, args, g_current_record);
            if (reapply_ret >= 0) {
                ret = reapply_ret;
                g_rr_framework->last_syscall_mutated = true;
                RR_INFO("🎯 FUZZING: Aux mutation reapplied to guest, new ret=%ld", (long)ret);
            }
        }
        
        /* Pure Replay success: return directly */
        RR_VERBOSE("REPLAY: Pure replay succeeded, ret=%d", (int)ret);
        goto replay_success;
        
try_hybrid:
        /* Continue with existing hybrid logic */
        {}
    }

    /* No-aux-data path: In FUZZING mode, return recorded retval for fd-operating syscalls
     * that would fail EBADF (accept was pure-replayed, no real kernel fd created).
     * These syscalls have has_aux_data=False so they skip the block above entirely. */
    if (!g_current_record->has_aux_data && g_rr_framework->mode == RR_MODE_FUZZING) {
#ifdef TARGET_NR_flock
        if (num == TARGET_NR_flock) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING flock() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_fcntl
        if (num == TARGET_NR_fcntl) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING fcntl() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_fcntl64
        if (num == TARGET_NR_fcntl64) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING fcntl64() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_select
        if (num == TARGET_NR_select) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING select() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR__newselect
        if (num == TARGET_NR__newselect) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING _newselect() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_poll
        if (num == TARGET_NR_poll) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING poll() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_ppoll
        if (num == TARGET_NR_ppoll) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING ppoll() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_setsockopt
        if (num == TARGET_NR_setsockopt) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING setsockopt() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_getsockopt
        if (num == TARGET_NR_getsockopt) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING getsockopt() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
        /* Network setup syscalls: return recorded values to avoid real socket creation.
         * Creating real sockets during silent_replay_mode causes port conflicts and
         * binary divergence (e.g., EADDRINUSE from bind → binary exits → parent exits
         * before reaching fork_point, giving 0 results for deep fork_points like idx=505).
         * All subsequent socket operations (accept, read, write) are handled by pure replay
         * via aux_data, so no real socket infrastructure is needed. */
#ifdef TARGET_NR_socket
        if (num == TARGET_NR_socket) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING socket() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_bind
        if (num == TARGET_NR_bind) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING bind() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_listen
        if (num == TARGET_NR_listen) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING listen() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_recvmsg
        if (num == TARGET_NR_recvmsg) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING recvmsg() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_sendmsg
        if (num == TARGET_NR_sendmsg) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING sendmsg() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_accept
        if (num == TARGET_NR_accept) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING accept() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_accept4
        if (num == TARGET_NR_accept4) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING accept4() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
        /* ioctl with no aux_data: return recorded retval (e.g., ENOTTY=-25 for tty check on
         * socket fd). Without bypass, HYBRID ioctl on a virtual fd returns EBADF which drives
         * the binary into unexpected error-handling paths and blocks parent advancement to
         * deep fork_points. All ioctl in this trace return -25 (ENOTTY), so bypass is safe. */
#ifdef TARGET_NR_ioctl
        if (num == TARGET_NR_ioctl) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING ioctl() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
        /* wait4/waitpid: in fork-per-request servers (uhttpd), the parent waits for each
         * child after the HTTP request is handled. Without bypass, HYBRID wait4 would block
         * waiting for the (suppressed) child PID, stalling parent advancement to fork_point.
         * Return recorded retval (child PID or -ECHILD) without actually waiting. */
#ifdef TARGET_NR_wait4
        if (num == TARGET_NR_wait4) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING wait4() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
#ifdef TARGET_NR_waitpid
        if (num == TARGET_NR_waitpid) {
            ret = g_current_record->retval;
            RR_VERBOSE("REPLAY: FUZZING waitpid() no-aux bypass, retval=%d", (int)ret);
            goto replay_success;
        }
#endif
    }

#ifdef TARGET_NR_clone
    if ((num == TARGET_NR_clone
#ifdef TARGET_NR_fork
        || num == TARGET_NR_fork
#endif
#ifdef TARGET_NR_vfork
        || num == TARGET_NR_vfork
#endif
        ) && g_current_record && g_current_record->has_aux_data) {
#endif
        rr_aux_data_t *aux = rr_aux_find(g_current_record->aux_data, 0);
        if (aux && aux->data && aux->size == sizeof(int64_t)) {
            pid_t recorded_pid = (pid_t)(*(int64_t *)aux->data);
            RR_VERBOSE("REPLAY_SYSCALL: Recorded child PID=%d", recorded_pid);
            /* TODO: establish recorded→replay PID mapping */
        }
    }

    /* 
     * Path 2: Hybrid Replay (Traditional mode)
     * - Apply FD mapping
     * - Support Fuzzing mutations
     * - Snapshot management
     * - Execute real syscall
     */
    RR_VERBOSE("REPLAY_SYSCALL: Hybrid replay path for syscall %d", num);

#ifdef TARGET_NR_read
    /* 🔥 Special Case: When read returns 0 (EOF), directly return 0 even without aux_data */
    if (num == TARGET_NR_read && ret == 0) {
        RR_VERBOSE("REPLAY_SYSCALL: read returned 0 (EOF), returning directly without real syscall");
        goto replay_success;
    }
#endif

    /* ✅ 2025-11-17: IO Return Value Mutation - Return value override in Hybrid mode */
    /* Key fix: Check if return value override is needed before executing real syscall */
    /* If overridden, skip real syscall and return the overridden value directly */
    if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_retval_override()) {
        abi_long original_ret = ret;
        ret = rr_fuzz_get_retval_override();  /* Get override value and clear flag */

        RR_INFO("🎯 IO RETVAL OVERRIDE (Hybrid): syscall %d (%s): %ld → %ld",
                num, rr_get_syscall_name_fast(num), (long)original_ret, (long)ret);

        fprintf(stderr, "[REPLAY-HYBRID] 🎯 RETVAL OVERRIDE: %ld → %ld\n", (long)original_ret, (long)ret);
        fflush(stderr);

        /* ✅ 2025-11-17: Buffer Fill in Hybrid path */
        if (rr_fuzz_has_buffer_fill()) {
            target_ulong buf_addr = 0;
            size_t buf_size = 0;
            const uint8_t *pattern = NULL;

            size_t fill_size = rr_fuzz_get_buffer_fill(&buf_addr, &buf_size, &pattern);

            if (fill_size > 0 && buf_addr != 0 && pattern != NULL) {
                if (cpu_memory_rw_debug(env_cpu(env), buf_addr, (uint8_t *)pattern, fill_size, 1) == 0) {
                    fprintf(stderr, "[REPLAY-HYBRID] 🎨 BUFFER FILLED: addr=0x%lx, size=%zu\n",
                            (unsigned long)buf_addr, fill_size);
                    fflush(stderr);
                }
            }
        }

        /* Skip real syscall execution, return overridden value directly */
        goto replay_success;
    }

    /* Apply FD mapping */
    apply_fd_mapping(args, num);

    /* TODO(P1): Fuzzing mutation logic will be added after mapping loop closure is complete */

    /* Automatic snapshot management */
    rr_snapshot_auto_manage(num, g_rr_framework->replay_index);

    /* Suppress fork/clone/vfork in silent_replay_mode and skip interleaved child records.
     *
     * In fork-per-request servers (e.g. uhttpd), the trace file interleaves child records
     * immediately after each parent fork record.  File order:
     *   [parent fork(ret=child_pid)] [child fork(ret=0)] [child sig...] ... [parent wait4(ret=child_pid)]
     *
     * Without skipping, the child records are consumed by the NR-mismatch catch-all but
     * with incorrect replay_index accounting, causing the parent to diverge from its true
     * syscall sequence and eventually crash (SIGSEGV) before reaching fork_point.
     *
     * Fix: after suppressing the parent fork, read ahead in the trace file, discarding
     * child records, until the parent's wait4/waitpid with retval==child_pid is found.
     * That wait4 record is saved in g_child_skip_pending_record so the parent application's
     * subsequent wait4 call consumes the correct record. */
    if (g_rr_framework->silent_replay_mode) {
        bool is_fork_call = false;
#ifdef TARGET_NR_fork
        if (num == TARGET_NR_fork) is_fork_call = true;
#endif
#ifdef TARGET_NR_vfork
        if (num == TARGET_NR_vfork) is_fork_call = true;
#endif
#ifdef TARGET_NR_clone
        if (num == TARGET_NR_clone) is_fork_call = true;
#endif
        if (is_fork_call) {
            /* Use recorded parent retval (child_pid); pure replay may have set ret=-1. */
            abi_long child_pid = g_current_record ? (abi_long)g_current_record->retval : 0;
            ret = child_pid;
            fprintf(stderr, "[CHILD-SKIP] PID=%d fork suppressed at replay_idx=%u child_pid=%ld, skipping child records\n",
                    getpid(), g_rr_framework->replay_index, (long)child_pid);

            /* Skip child records until parent's wait4/waitpid(retval==child_pid). */
            if (child_pid > 0) {
                syscall_record_t *rec;
                int skipped = 0;
                while ((rec = read_next_record()) != NULL) {
                    bool is_parent_wait = false;
#ifdef TARGET_NR_wait4
                    if (rec->syscall_nr == TARGET_NR_wait4 &&
                        (abi_long)rec->retval == child_pid) is_parent_wait = true;
#endif
#ifdef TARGET_NR_waitpid
                    if (rec->syscall_nr == TARGET_NR_waitpid &&
                        (abi_long)rec->retval == child_pid) is_parent_wait = true;
#endif
                    if (is_parent_wait) {
                        /* Save parent's wait4 for when the application calls wait4 next. */
                        g_child_skip_pending_record = rec;
                        fprintf(stderr, "[CHILD-SKIP] PID=%d found parent wait4(retval=%ld) after skipping %d child records\n",
                                getpid(), (long)child_pid, skipped);
                        break;
                    }
                    /* Discard child record. */
                    skipped++;
                    rr_record_dispose(rec);
                }
                if (!g_child_skip_pending_record) {
                    fprintf(stderr, "[CHILD-SKIP] PID=%d WARNING: no wait4 found after %d skipped records (EOF?)\n",
                            getpid(), skipped);
                }
            }
            goto replay_success;
        }
    }

    /* 🔥 Hybrid Mode: All syscalls execute real calls, mappings handled by post_hook */
    /* Address mapping for special syscalls like mmap is completed in post_hook */

    /* 🔥 Key Fix: Hybrid mode must clean record and advance index before returning */
    g_pending_post_record = g_current_record;
    g_current_record = NULL;
    g_rr_framework->replay_index++;

    /* Set flag to notify post_hook not to double process */
    g_syscall_already_consumed = true;

    /* Return -1 to let QEMU execute real syscall (with mutated arguments) */
    RR_VERBOSE("REPLAY_SYSCALL: Hybrid mode, record cleaned, executing real syscall %d", num);
    return -1;

    /* This is the common success path for Pure Replay or Overridden Hybrid Replay */
replay_success:
    if (g_current_record) {
        g_pending_post_record = g_current_record;
        g_current_record = NULL;
    }

    g_rr_framework->replay_index++;
    g_syscall_already_consumed = true;

    /* Apply return value override (IO return value mutation) */
    if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_retval_override()) {
        abi_long original_ret = ret;
        ret = rr_fuzz_get_retval_override();  // This clears the flag automatically

        RR_INFO("🎯 IO RETVAL OVERRIDE: syscall %d (%s): ret_before=%ld → ret_after=%ld",
                num, rr_get_syscall_name_fast(num), (long)original_ret, (long)ret);

        fprintf(stderr, "[REPLAY] 🎯 RETVAL OVERRIDE: before=%ld → after=%ld\n",
                (long)original_ret, (long)ret);
        fflush(stderr);
    }

    /* Generalized Buffer Fill - Fill IO buffer content */
    if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_buffer_fill()) {
        target_ulong buf_addr = 0;
        size_t buf_size = 0;
        const uint8_t *pattern = NULL;

        size_t fill_size = rr_fuzz_get_buffer_fill(&buf_addr, &buf_size, &pattern);

        if (fill_size > 0 && buf_addr != 0 && pattern != NULL) {
            /* Fill guest buffer */
            if (cpu_memory_rw_debug(env_cpu(env), buf_addr, (uint8_t *)pattern, fill_size, 1) == 0) {
                RR_INFO("🎨 BUFFER FILLED: syscall %d (%s): addr=0x%lx, size=%zu",
                        num, rr_get_syscall_name_fast(num), (unsigned long)buf_addr, fill_size);

                fprintf(stderr, "[REPLAY] 🎨 BUFFER FILLED: addr=0x%lx, size=%zu (first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x)\n",
                        (unsigned long)buf_addr, fill_size,
                        pattern[0], pattern[1], pattern[2], pattern[3],
                        pattern[4], pattern[5], pattern[6], pattern[7]);
                fflush(stderr);
            } else {
                RR_WARN("Failed to fill buffer at addr=0x%lx, size=%zu", (unsigned long)buf_addr, fill_size);
            }
        }
    }

    /* Dynamic trace: Syscall exit (binary replay path) */
#ifdef RR_ENABLE_DYNAMIC_TRACE
    rr_dynamic_trace_syscall_exit(env, num, (uint64_t*)args, ret,
                                    g_rr_framework->replay_index - 1, false);
#endif

    RR_VERBOSE("REPLAY_SYSCALL: Successfully replayed syscall %u: %d -> %d",
               g_rr_framework->replay_index - 1, num, (int)ret);
    return ret;
}
