/**
 * RR-Fuzz Mutation Engine
 * Implements fuzzing instruction application and parameter mutation
 */

#include "rr_framework.h"
#include "rr_syscall_dispatch.h"

/* ==================== Optimization Flags ==================== */
#define FUZZ_ENABLE_DEBUG_LOG 1

#if FUZZ_ENABLE_DEBUG_LOG
#define FUZZ_DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__); fflush(stderr)
#else
#define FUZZ_DEBUG_LOG(...) do {} while(0)
#endif

/* ==================== Global State ==================== */

FuzzInstruction g_fuzz_instructions[FUZZ_MAX_INSTRUCTIONS];
size_t g_instruction_count = 0;

bool g_has_retval_override = false;
abi_long g_retval_override = 0;

bool g_has_buffer_fill = false;           
target_ulong g_buffer_fill_addr = 0;      
size_t g_buffer_fill_size = 0;            
uint8_t g_buffer_fill_pattern[1024];      
size_t g_buffer_fill_pattern_len = 0;     

typedef struct {
    uint64_t total_mutations;       
    uint64_t arg_mutations;         
    uint64_t buffer_mutations;      
    uint64_t boundary_tests;        
    uint64_t retval_mutations;      
} fuzz_stats_t;

static int get_input_io_buffer_arg_index(int syscall_nr);
fuzz_stats_t g_fuzz_stats = {0};

/**
 * Load Fuzz instructions from shared memory
 */
int rr_fuzz_load_from_shared_memory(void *shm_ptr, int variant_idx)
{
    if (!shm_ptr) {
        RR_WARN("Shared memory pointer is NULL");
        return -1;
    }

    FuzzSharedMemory *shm = (FuzzSharedMemory *)shm_ptr;

    if (shm->magic != FUZZ_MAGIC) {
        RR_ERROR("Invalid shared memory magic: 0x%08x (expected 0x%08x) at %p", 
                 shm->magic, FUZZ_MAGIC, shm);
        return -1;
    }

    uint32_t expected_checksum = shm->magic ^ shm->sequence ^ shm->num_variants ^ shm->fork_point ^ shm->current_depth;
    
    RR_INFO("SHM DUMP BEFORE CHECKSUM: magic=0x%08x, seq=%u, variants=%u, fp=%u, depth=%u",
            shm->magic, shm->sequence, shm->num_variants, shm->fork_point, shm->current_depth);

    if (shm->checksum != expected_checksum) {
        RR_WARN("Shared memory checksum mismatch in child %d! PID=%d", variant_idx, getpid());
        RR_WARN("  Header Dump: magic=0x%08x, seq=%u, variants=%u, fp=%u, depth=%u",
                shm->magic, shm->sequence, shm->num_variants, shm->fork_point, shm->current_depth);
        RR_WARN("  Checksum: got 0x%08x, expected 0x%08x",
                shm->checksum, expected_checksum);
        g_instruction_count = 0;
        return -2; // Unique error code
    }

    if (variant_idx >= 0 && variant_idx < (int)shm->num_variants) {
        FuzzVariant *variant = &shm->variants[variant_idx];
        g_instruction_count = variant->instruction_count;
        
        if (g_instruction_count > RR_FUZZ_MAX_INSTRUCTIONS) {
            RR_ERROR("Too many instructions for variant %d: %zu (max %d)", 
                     variant_idx, g_instruction_count, RR_FUZZ_MAX_INSTRUCTIONS);
            return -3; // Unique error code
        }
        
        memcpy(g_fuzz_instructions, variant->instructions, 
               sizeof(FuzzInstruction) * g_instruction_count);
        RR_INFO("Loaded %zu fuzz instructions (variant %d) from shared memory at %p", g_instruction_count, variant_idx, shm);
        return 0;
    } else {
        RR_WARN("Variant index %d out of bounds (num_variants=%u)", variant_idx, shm->num_variants);
        g_instruction_count = 0;
        return -4; // Unique error code
    }

}


static int apply_mutations_for_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr) {
    int has_buffer_mutation = 0;
    
    if (g_instruction_count == 0) {
        return 0;
    }

    const char *syscall_name = rr_get_syscall_name_fast(syscall_nr);
    
    for (size_t i = 0; i < g_instruction_count; i++) {
        FuzzInstruction *instr = &g_fuzz_instructions[i];
        
        if (instr->syscall_index != syscall_index) {
            continue;
        }
        
        if (instr->arg_index != 0xFF && instr->arg_index >= 8) {
            continue;
        }
        
        FUZZ_DEBUG_LOG("[APPLY] PID=%d, syscall_index=%u, nr=%d (%s), cmd=%d\n", 
                getpid(), syscall_index, syscall_nr, syscall_name ? syscall_name : "unknown", instr->cmd);

        switch (instr->cmd) {
            case FUZZ_CMD_MUTATE_ARG:
                if (instr->arg_index == 0xFF) {
                    if (instr->data_len >= sizeof(abi_long)) {
                        g_retval_override = *(abi_long *)instr->data;
                        g_has_retval_override = true;

                        int buf_arg_idx = get_input_io_buffer_arg_index(syscall_nr);
                        if (buf_arg_idx >= 0 && g_retval_override > 0) {
                            target_ulong buf_addr = args[buf_arg_idx];
                            if (buf_addr != 0) {
                                const uint8_t *pattern = NULL;
                                size_t pattern_len = 0;
                                if (instr->data_len > sizeof(abi_long)) {
                                    pattern = instr->data + sizeof(abi_long);
                                    pattern_len = instr->data_len - sizeof(abi_long);
                                }
                                rr_fuzz_set_buffer_fill(buf_addr, (size_t)g_retval_override, pattern, pattern_len);
                            }
                        }
                        g_fuzz_stats.retval_mutations++;
                    }
                    break;
                }

                if (instr->data_len >= sizeof(abi_long)) {
                    abi_long new_value = *(abi_long *)instr->data;
                    args[instr->arg_index] = new_value;
                    g_fuzz_stats.arg_mutations++;
                }
                break;

            case FUZZ_CMD_REPLACE_BUFFER:
                if (instr->data_len > 0) {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0) {
                        if (cpu_memory_rw_debug(env_cpu(env), addr, instr->data, instr->data_len, 1) == 0) {
                            g_fuzz_stats.buffer_mutations++;
                            has_buffer_mutation = 1;
                        }
                    }
                }
                break;

            case FUZZ_CMD_OVERWRITE_AT_OFFSET:
                {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0 && instr->size > 0 && instr->size <= instr->data_len) {
                        target_ulong target_addr = addr + instr->offset;
                        if (cpu_memory_rw_debug(env_cpu(env), target_addr, instr->data, instr->size, 1) == 0) {
                            has_buffer_mutation = 1;
                            g_fuzz_stats.buffer_mutations++;
                            FUZZ_DEBUG_LOG("[OVERWRITE] ✅ Wrote %u bytes to 0x%lx\n", instr->size, (unsigned long)target_addr);
                        }
                    }
                }
                break;
                
            case FUZZ_CMD_FLIP_BITS:
                {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0 && instr->data_len >= 4) {
                        uint32_t offset = *(uint32_t *)instr->data;
                        uint32_t mask_len = instr->data_len - 4;
                        uint8_t *bit_mask = instr->data + 4;
                        uint8_t *buffer = g_malloc(mask_len);
                        if (cpu_memory_rw_debug(env_cpu(env), addr + offset, buffer, mask_len, 0) == 0) {
                            for (uint32_t j = 0; j < mask_len; j++) buffer[j] ^= bit_mask[j];
                            if (cpu_memory_rw_debug(env_cpu(env), addr + offset, buffer, mask_len, 1) == 0) {
                                has_buffer_mutation = 1;
                                g_fuzz_stats.buffer_mutations++;
                            }
                        }
                        g_free(buffer);
                    }
                }
                break;

            case FUZZ_CMD_TRUNCATE:
                /* Reduce retval to simulate a shorter read/recv, causing
                 * the program to process fewer bytes than originally recorded. */
                if (instr->data_len >= sizeof(int32_t)) {
                    int32_t trunc_size = *(int32_t *)instr->data;
                    if (trunc_size >= 0) {
                        g_retval_override = (abi_long)trunc_size;
                        g_has_retval_override = true;
                        g_fuzz_stats.retval_mutations++;
                        FUZZ_DEBUG_LOG("[TRUNCATE] retval → %d\n", trunc_size);
                    }
                }
                break;

            case FUZZ_CMD_EXTEND:
                /* Inflate retval to simulate more data received, potentially
                 * causing the program to read past a legitimate buffer boundary. */
                if (instr->data_len >= sizeof(int32_t)) {
                    int32_t ext_size = *(int32_t *)instr->data;
                    if (ext_size > 0) {
                        g_retval_override = (abi_long)ext_size;
                        g_has_retval_override = true;
                        g_fuzz_stats.retval_mutations++;
                        FUZZ_DEBUG_LOG("[EXTEND] retval → %d\n", ext_size);
                    }
                }
                break;

            case FUZZ_CMD_INTERESTING_VALUES:
                /* Inject a boundary/magic value into an argument or retval.
                 * Payload is a single int64_t (e.g. -1, 0, INT_MAX, UINT_MAX). */
                if (instr->data_len >= sizeof(int64_t)) {
                    int64_t interesting = *(int64_t *)instr->data;
                    if (instr->arg_index == 0xFF) {
                        g_retval_override = (abi_long)interesting;
                        g_has_retval_override = true;
                    } else if (instr->arg_index < 6) {
                        args[instr->arg_index] = (abi_long)interesting;
                    }
                    g_fuzz_stats.arg_mutations++;
                    FUZZ_DEBUG_LOG("[INTERESTING_VALUES] arg[%u] = %ld\n",
                        instr->arg_index, (long)interesting);
                }
                break;

            case FUZZ_CMD_LIGHT_MUTATION:
                /* Flip a single byte at a given offset within the buffer —
                 * minimal disturbance useful for coverage-guided refinement. */
                {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0 && instr->data_len >= 2) {
                        uint32_t offset   = (uint32_t)instr->data[0];
                        uint8_t flip_mask = instr->data[1];
                        uint8_t orig_byte = 0;
                        if (cpu_memory_rw_debug(env_cpu(env), addr + offset, &orig_byte, 1, 0) == 0) {
                            orig_byte ^= flip_mask;
                            if (cpu_memory_rw_debug(env_cpu(env), addr + offset, &orig_byte, 1, 1) == 0) {
                                has_buffer_mutation = 1;
                                g_fuzz_stats.buffer_mutations++;
                                FUZZ_DEBUG_LOG("[LIGHT_MUTATION] byte@+%u ^= 0x%02x\n", offset, flip_mask);
                            }
                        }
                    }
                }
                break;

            case FUZZ_CMD_MUTATE_FLAGS:
                if (instr->data_len >= sizeof(uint64_t)) {
                    uint64_t flag_mask = *(uint64_t *)instr->data;
                    if (instr->arg_index != 0xFF && instr->arg_index < 6) {
                        abi_long old_val = args[instr->arg_index];
                        args[instr->arg_index] = old_val ^ (abi_long)flag_mask;
                        g_fuzz_stats.arg_mutations++;
                        FUZZ_DEBUG_LOG("[MUTATE_FLAGS] arg[%u]: 0x%lx ^ 0x%lx = 0x%lx\n",
                            instr->arg_index, (unsigned long)old_val,
                            (unsigned long)flag_mask,
                            (unsigned long)args[instr->arg_index]);
                    }
                }
                break;

            case FUZZ_CMD_BOUNDARY_VALUE:
                if (instr->data_len >= sizeof(int64_t)) {
                    int64_t boundary = *(int64_t *)instr->data;
                    if (instr->arg_index != 0xFF && instr->arg_index < 6) {
                        args[instr->arg_index] = (abi_long)boundary;
                        g_fuzz_stats.boundary_tests++;
                    } else if (instr->arg_index == 0xFF) {
                        g_retval_override = (abi_long)boundary;
                        g_has_retval_override = true;
                        g_fuzz_stats.boundary_tests++;
                    }
                    FUZZ_DEBUG_LOG("[BOUNDARY_VALUE] arg[%u] = %ld\n",
                        instr->arg_index, (long)boundary);
                }
                break;

            default:
                break;
        }
        g_fuzz_stats.total_mutations++;
    }
    return has_buffer_mutation;
}

int rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr)
{
    if (!g_rr_framework || g_rr_framework->mode != RR_MODE_FUZZING) {
        return 0;
    }
    return apply_mutations_for_syscall(env, syscall_index, args, syscall_nr);
}

bool rr_fuzz_has_retval_override(void) { return g_has_retval_override; }

abi_long rr_fuzz_get_retval_override(void)
{
    abi_long ret = g_retval_override;
    g_has_retval_override = false;
    return ret;
}

void rr_fuzz_clear_retval_override(void) { g_has_retval_override = false; g_retval_override = 0; }

static int get_input_io_buffer_arg_index(int syscall_nr)
{
    switch (syscall_nr) {
        case TARGET_NR_read:
        case TARGET_NR_readv:
        case TARGET_NR_pread64:
#ifdef TARGET_NR_recv
        case TARGET_NR_recv:
#endif
#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
#endif
            return 1;
        default:
            return -1;
    }
}

void rr_fuzz_set_buffer_fill(target_ulong buf_addr, size_t size, const uint8_t *pattern, size_t pattern_len)
{
    if (size > sizeof(g_buffer_fill_pattern)) size = sizeof(g_buffer_fill_pattern);
    g_buffer_fill_addr = buf_addr;
    g_buffer_fill_size = size;
    g_buffer_fill_pattern_len = pattern_len;
    if (pattern && pattern_len > 0) {
        for (size_t i = 0; i < size; i++) g_buffer_fill_pattern[i] = pattern[i % pattern_len];
    } else {
        for (size_t i = 0; i < size; i++) g_buffer_fill_pattern[i] = (uint8_t)(i & 0xFF);
    }
    g_has_buffer_fill = true;
}

bool rr_fuzz_has_buffer_fill(void) { return g_has_buffer_fill; }

size_t rr_fuzz_get_buffer_fill(target_ulong *out_addr, size_t *out_size, const uint8_t **out_pattern)
{
    if (!g_has_buffer_fill) return 0;
    if (out_addr) *out_addr = g_buffer_fill_addr;
    if (out_size) *out_size = g_buffer_fill_size;
    if (out_pattern) *out_pattern = g_buffer_fill_pattern;
    g_has_buffer_fill = false;
    return g_buffer_fill_size;
}

void rr_fuzz_clear_buffer_fill(void) { g_has_buffer_fill = false; }

void rr_fuzz_get_stats(uint64_t *total, uint64_t *arg_mut, uint64_t *buf_mut, uint64_t *boundary)
{
    if (total) *total = g_fuzz_stats.total_mutations;
    if (arg_mut) *arg_mut = g_fuzz_stats.arg_mutations;
    if (buf_mut) *buf_mut = g_fuzz_stats.buffer_mutations;
}

void rr_fuzz_print_stats(void)
{
    if (g_fuzz_stats.total_mutations == 0) return;
    RR_INFO("=== FUZZ ENGINE STATISTICS ===");
    RR_INFO("Total mutations: %lu", g_fuzz_stats.total_mutations);
    RR_INFO("==============================");
}

void rr_fuzz_cleanup(void)
{
    if (g_fuzz_stats.total_mutations > 0) rr_fuzz_print_stats();
    g_instruction_count = 0;
    memset(g_fuzz_instructions, 0, sizeof(g_fuzz_instructions));
    memset(&g_fuzz_stats, 0, sizeof(g_fuzz_stats));
}
