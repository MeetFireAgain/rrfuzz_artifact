/**
 * RR-Fuzz Phase 1: aux_data Mutation Engine
 * 
 * Implements various mutation strategies for aux_data used in Pure Replay + Fuzzing integration.
 * 
 * Design Concept:
 * 1. Mutate aux_data after successful Pure Replay.
 * 2. Re-apply mutated data back to guest memory for deterministic Fuzzing.
 * 3. Support multiple mutation strategies to cover various test scenarios.
 */

#include "rr_framework.h"
#include "rr_aux_data.h"
#include "rr_syscall_dispatch.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* External Variables */

// Fuzz Instructions (from rr_fuzz_engine.c)
 
// Fuzz Statistics (from rr_fuzz_engine.c)
typedef struct {
    uint64_t total_mutations;
    uint64_t arg_mutations;
    uint64_t buffer_mutations;
    uint64_t boundary_tests;
} fuzz_stats_t;

extern fuzz_stats_t g_fuzz_stats;

/* Helper Functions */

/**
 * Generate a random byte.
 */
static uint8_t random_byte(void) {
    static bool initialized = false;
    if (!initialized) {
        srand(time(NULL));
        initialized = true;
    }
    return (uint8_t)(rand() % 256);
}

/**
 * Find aux_data for a specific arg_mask.
 * 
 * arg_mask is a bitmask of the argument index (e.g., arg_mask=1 for arg[0]).
 */
static rr_aux_data_t *find_aux_data_by_arg_mask(rr_aux_data_t *head, uint8_t target_mask) {
    rr_aux_data_t *current = head;
    while (current) {
        if (current->arg_mask == target_mask) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

/* Mutation Strategy Implementation */

/**
 * Strategy 1: Mutate aux_data buffer.
 * 
 * Directly replaces the data in aux_data.
 */
static void mutate_aux_buffer(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data) {
        return;
    }
    
    // Limit mutation length, do not exceed the actual boundary of aux_data
    uint32_t copy_len = (instr->data_len < aux->size) ? instr->data_len : aux->size;
    
    // Copy mutation data
    memcpy(aux->data, instr->data, copy_len);
    
    RR_INFO("FUZZ_AUX: Mutated buffer, copied %u/%u bytes", copy_len, aux->size);
    g_fuzz_stats.buffer_mutations++;
}

/**
 * Strategy 2: Bit Flipping.
 * 
 * Randomly flips bits in the aux_data buffer.
 */
static void flip_bits(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data || aux->size == 0) {
        return;
    }
    
    uint32_t flip_count = 0;
    
    // Read flipping probability (0-100) from instr->data[0]
    uint32_t flip_prob = (instr->data_len > 0) ? instr->data[0] : 1;
    if (flip_prob == 0) flip_prob = 1;
    if (flip_prob > 100) flip_prob = 100;
    
    // Traverse each byte
    for (uint32_t i = 0; i < aux->size; i++) {
        // Decide whether to flip based on probability
        if ((rand() % 100) < flip_prob) {
            // Randomly select a bit to flip
            int bit = rand() % 8;
            aux->data[i] ^= (1 << bit);
            flip_count++;
        }
    }
    
    RR_INFO("FUZZ_AUX: Flipped %u bits (prob=%u%%, size=%u)", 
            flip_count, flip_prob, aux->size);
    g_fuzz_stats.arg_mutations++;
}

/**
 * Strategy 3: Truncate Data.
 * 
 * Reduces the size of aux_data.
 */
static void truncate_data(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data || aux->size == 0) {
        return;
    }
    
    __attribute__((unused)) uint32_t old_size = aux->size;
    
    // Read truncation ratio from instr->data[0]; defaults to halving if not specified.
    if (instr->data_len > 0 && instr->data[0] > 0 && instr->data[0] < 100) {
        // data[0] represents the percentage to keep
        aux->size = (aux->size * instr->data[0]) / 100;
    } else {
        // Default to halving
        aux->size = aux->size / 2;
    }
    
    // Maintain at least 1 byte
    if (aux->size == 0) {
        aux->size = 1;
    }
    
    RR_INFO("FUZZ_AUX: Truncated %u → %u bytes", old_size, aux->size);
    g_fuzz_stats.boundary_tests++;
}

/**
 * Strategy 4: Extend Data.
 * 
 * Increases the size of aux_data (padded with zeros or random data).
 */
static void extend_data(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data) {
        return;
    }
    
    __attribute__((unused)) uint32_t old_size = aux->size;
    uint32_t new_size;
    
    // Read absolute extension byte count from instr->data (not a multiplier!)
    uint32_t extend_by;
    if (instr->data_len >= 4) {
        // Python side sends 4-byte absolute value via struct.pack('I', extend_by)
        memcpy(&extend_by, instr->data, 4);
    } else {
        // Fallback default
        extend_by = 64;
    }

    new_size = aux->size + extend_by;

    // Boost max size limit to support buffer overflow tests (1024 bytes)
    if (new_size > 1024) {
        new_size = 1024;
    }
    
    // Skip if no growth
    if (new_size <= aux->size) {
        RR_VERBOSE("FUZZ_AUX: Extend skipped (already max size)");
        return;
    }
    
    // Reallocate memory
    uint8_t *new_data = g_malloc(new_size);
    memcpy(new_data, aux->data, old_size);
    
    // Fill mode: read from instr->data[1] (0=zeros, 1=random)
    uint8_t fill_mode = (instr->data_len > 1) ? instr->data[1] : 0;
    if (fill_mode == 1) {
        // Fill with random bytes
        for (uint32_t i = old_size; i < new_size; i++) {
            new_data[i] = random_byte();
        }
    } else {
        // Fill with zeros
        memset(new_data + old_size, 0, new_size - old_size);
    }
    
    // Replace original data
    g_free(aux->data);
    aux->data = new_data;
    aux->size = new_size;
    
    RR_INFO("FUZZ_AUX: Extended %u → %u bytes (fill_mode=%u)", 
            old_size, new_size, fill_mode);
    g_fuzz_stats.boundary_tests++;
}

/**
 * Phase 1 Strategy: Lightweight Mutation
 * 
 * Flips only 1-2 bits to minimize destructiveness.
 * Suitable for early phase Fuzzing to avoid immediate crashes.
 */
static void mutate_light(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data || aux->size == 0) {
        return;
    }
    
    // Default: flip only 1 bit
    uint32_t flip_count = 1;
    
    // If instruction provides data, the first byte specifies the number of flips (1-3)
    if (instr->data_len > 0 && instr->data[0] > 0) {
        flip_count = (instr->data[0] % 3) + 1;  // 1-3 bits
    }
    
    // Flip the specified number of bits
    for (uint32_t i = 0; i < flip_count; i++) {
        // Randomly select a byte
        uint32_t byte_idx = rand() % aux->size;
        // Randomly select a bit
        uint8_t bit_idx = rand() % 8;
        // Flip
        aux->data[byte_idx] ^= (1 << bit_idx);
    }
    
    RR_INFO("FUZZ_AUX: Light mutation - flipped %u bits in %u bytes", 
            flip_count, aux->size);
    g_fuzz_stats.arg_mutations++;
}

/**
 * Strategy 5: Interesting Values Injection.
 * 
 * Injects specific "interesting" values like boundary values, magic numbers, etc.
 */
/**
 * @brief Strategy 5: Interesting Values Injection (Vulnerability Patterns)
 * 
 * Intelligently injects known vulnerability payloads based on syscall type.
 * This is a critical strategy for discovering specific types of flaws: 
 * format strings, command injection, and buffer overflows.
 * 
 * **Supported Patterns**:
 * - `getrandom`: All-zeros/all-ones/repeating patterns (tests for weak RNG)
 * - `read/recv*`:
 *    - Format String: `%s%n`, `%p`
 *    - Buffer Overflow: Long strings ('A' * N)
 *    - Integer Overflow: MAX_INT, 0xFFFFFFFF
 *    - Command Injection: `$(id)`
 *    - Path Traversal: `../../etc/passwd`
 * 
 * @param aux Target aux_data
 * @param instr Mutation instruction
 * @param syscall_nr Syscall number
 */
static void inject_interesting_values(rr_aux_data_t *aux, const FuzzInstruction *instr,
                                      int syscall_nr) {
    if (!aux || !aux->data || aux->size == 0) {
        return;
    }
    
    // Inject different values based on syscall type
    switch (syscall_nr) {
        case TARGET_NR_getrandom: {
            /* Random data variants: all zeros, all ones, repeating patterns */
            if (instr->data_len > 0) {
                uint8_t pattern = instr->data[0];
                memset(aux->data, pattern, aux->size);
                RR_INFO("FUZZ_AUX: Injected pattern 0x%02x (getrandom)", pattern);
            } else {
                // Default: all zeros
                memset(aux->data, 0x00, aux->size);
                RR_INFO("FUZZ_AUX: Injected all zeros (getrandom)");
            }
            break;
        }
        
        case TARGET_NR_read:
#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64:
#endif
#ifdef TARGET_NR_recv
        case TARGET_NR_recv:
#endif
#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
#endif
        {
            /* Targeted: Support for various vulnerability pattern injections */
            if (instr->data_len > 0) {
                uint8_t pattern_type = instr->data[0] % 8;  // 8 modes

                switch (pattern_type) {
                    case 0: {
                        // Format string attack
                        const char *fmt_patterns[] = {"%s%s%s%n", "%p%p%p", "%x%x%x"};
                        const char *pattern = fmt_patterns[instr->data[1] % 3];
                        size_t pattern_len = strlen(pattern);
                        size_t copy_len = (pattern_len < aux->size) ? pattern_len : aux->size;
                        memcpy(aux->data, pattern, copy_len);
                        RR_INFO("FUZZ_AUX: Injected format string pattern");
                        break;
                    }
                    case 1: {
                        // Buffer overflow pattern (repeating character)
                        uint8_t overflow_char = (instr->data_len > 1) ? instr->data[1] : 0x41;  // 'A'
                        memset(aux->data, overflow_char, aux->size);
                        RR_INFO("FUZZ_AUX: Injected overflow pattern (0x%02x)", overflow_char);
                        break;
                    }
                    case 2: {
                        // NULL byte injection
                        memset(aux->data, 0x00, aux->size);
                        RR_INFO("FUZZ_AUX: Injected NULL bytes");
                        break;
                    }
                    case 3: {
                        // High-byte verification
                        memset(aux->data, 0xFF, aux->size);
                        RR_INFO("FUZZ_AUX: Injected high bytes (0xFF)");
                        break;
                    }
                    case 4: {
                        // Integer boundary values
                        if (aux->size >= 4) {
                            uint32_t boundary_vals[] = {0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF};
                            uint32_t val = boundary_vals[(instr->data[1] % 5)];
                            memcpy(aux->data, &val, 4);
                            RR_INFO("FUZZ_AUX: Injected boundary value 0x%08x", val);
                        }
                        break;
                    }
                    case 5: {
                        // Path traversal injection
                        const char *path_pattern = "/../../../etc/passwd";
                        size_t pattern_len = strlen(path_pattern);
                        size_t copy_len = (pattern_len < aux->size) ? pattern_len : aux->size;
                        memcpy(aux->data, path_pattern, copy_len);
                        RR_INFO("FUZZ_AUX: Injected path traversal");
                        break;
                    }
                    case 6: {
                        // Command injection pattern
                        const char *cmd_pattern = "$(id)";
                        size_t pattern_len = strlen(cmd_pattern);
                        size_t copy_len = (pattern_len < aux->size) ? pattern_len : aux->size;
                        memcpy(aux->data, cmd_pattern, copy_len);
                        RR_INFO("FUZZ_AUX: Injected command injection");
                        break;
                    }
                    default: {
                        // Generic magic byte injection
                        if (instr->data_len >= 4) {
                            memcpy(aux->data, instr->data + 1, (instr->data_len - 1 < aux->size) ? instr->data_len - 1 : aux->size);
                            RR_INFO("FUZZ_AUX: Injected custom magic bytes");
                        } else {
                            memset(aux->data, 0xFF, aux->size);
                            RR_INFO("FUZZ_AUX: Injected default 0xFF pattern");
                        }
                        break;
                    }
                }
            } else {
                // Fallback to original logic
                memset(aux->data, 0xFF, aux->size);
                RR_INFO("FUZZ_AUX: Injected 0xFF pattern (fallback)");
            }
            break;
        }
        
        default:
            // Other syscalls: Inject 0xFF pattern
            memset(aux->data, 0xFF, aux->size);
            RR_INFO("FUZZ_AUX: Injected 0xFF pattern (default)");
            break;
    }
    
    g_fuzz_stats.arg_mutations++;
}

/* Main Functions */

/**
 * Mutate data in aux_data.
 * 
 * This function traverses all Fuzz instructions and mutates the matching aux_data.
 */
/**
 * @brief Execute Aux Data Mutation (Entry Function).
 * 
 * Called during replay when a system call with aux_data (e.g., read/getrandom) is encountered.
 * Traverses current Fuzz instructions; if an aux mutation instruction for the syscall is found,
 * it modifies the content of the aux_data.
 * 
 * **Workflow**:
 * 1. Check if in Fuzzing mode and whether instructions exist.
 * 2. Traverse instructions, matching by syscall_index.
 * 3. Locate the corresponding aux_data node (based on arg_index).
 * 4. Invoke the specific mutation strategy function (e.g., mutate_aux_buffer, flip_bits, extend_data).
 * 
 * @param env CPU environment
 * @param record syscall record
 * @param args arguments
 * @param syscall_nr syscall number
 */
void rr_fuzz_mutate_aux_data(CPUArchState *env, syscall_record_t *record,
                              abi_long *args, int syscall_nr) {
    // Check prerequisites
    if (!record || !record->aux_data) {
        RR_VERBOSE("FUZZ_AUX: No aux_data to mutate");
        return;
    }
    
    if (g_rr_framework->mode != RR_MODE_FUZZING) {
        RR_VERBOSE("FUZZ_AUX: Not in fuzzing mode");
        return;
    }
    
    if (g_instruction_count == 0) {
        RR_VERBOSE("FUZZ_AUX: No fuzz instructions");
        return;
    }
    
    RR_VERBOSE("FUZZ_AUX: Mutating aux_data for syscall %d (index=%u)", 
              syscall_nr, record->index);
    
    // Iterate through all Fuzz instructions
    for (size_t i = 0; i < g_instruction_count; i++) {
        FuzzInstruction *instr = &g_fuzz_instructions[i];
        
        // Only process instructions matching current syscall index
        if (instr->syscall_index != record->index) {
            continue;
        }
        
        /* Locate aux_data: records store arg_mask as raw arg_index (0,1,2...) not (1<<n) */
        uint8_t arg_mask = instr->arg_index;
        rr_aux_data_t *aux = find_aux_data_by_arg_mask(record->aux_data, arg_mask);
        if (!aux) {
            RR_VERBOSE("FUZZ_AUX: No aux_data for arg[%u] (mask=0x%02x)", 
                      instr->arg_index, arg_mask);
            continue;
        }
        
        RR_VERBOSE("FUZZ_AUX: Found aux_data for arg[%u] (mask=0x%02x), size=%u, kind=%d",
                  instr->arg_index, arg_mask, aux->size, aux->kind);
        
        // Execute mutation based on command type
        switch (instr->cmd) {
            case FUZZ_CMD_MUTATE_AUX_BUFFER:
                mutate_aux_buffer(aux, instr);
                break;
                
            case FUZZ_CMD_FLIP_BITS:
                flip_bits(aux, instr);
                break;
                
            case FUZZ_CMD_TRUNCATE:
                truncate_data(aux, instr);
                break;
                
            case FUZZ_CMD_EXTEND:
                extend_data(aux, instr);
                break;
                
            case FUZZ_CMD_INTERESTING_VALUES:
                inject_interesting_values(aux, instr, syscall_nr);
                break;
            
            case FUZZ_CMD_LIGHT_MUTATION:
                mutate_light(aux, instr);
                break;
                
            default:
                RR_VERBOSE("FUZZ_AUX: Unknown command %d", instr->cmd);
                break;
        }
        
        g_fuzz_stats.total_mutations++;
    }
    
    RR_VERBOSE("FUZZ_AUX: Mutation complete");
}

