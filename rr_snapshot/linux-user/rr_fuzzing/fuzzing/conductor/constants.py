#!/usr/bin/env python3
"""
RR-Fuzz Constants and Command Definitions

This module contains all constants and command type definitions used throughout
the RR-Fuzz system. These values must remain consistent with the C-side definitions
(rr_constants.h and rr_framework.h).
"""

# ===== Fuzz command types (must match C-side definitions) =====
FUZZ_CMD_NONE = 0                    # No command
FUZZ_CMD_MUTATE_ARG = 1              # Mutate argument
FUZZ_CMD_REPLACE_BUFFER = 2          # Replace buffer
FUZZ_CMD_MUTATE_FLAGS = 3            # Mutate flags
FUZZ_CMD_BOUNDARY_VALUE = 4          # Boundary value
# Auxiliary data mutation commands
FUZZ_CMD_MUTATE_AUX_BUFFER = 5       # Mutate aux_data buffer
FUZZ_CMD_FLIP_BITS = 6               # Bit flip
FUZZ_CMD_TRUNCATE = 7                # Truncate
FUZZ_CMD_EXTEND = 8                  # Extend
FUZZ_CMD_INTERESTING_VALUES = 9      # Special values
FUZZ_CMD_LIGHT_MUTATION = 10         # Light mutation
# Precise memory overwrite command
FUZZ_CMD_OVERWRITE_AT_OFFSET = 11    # Overwrite at specific offset

# ===== Shared memory constants (must match rr_constants.h) =====
FUZZ_MAGIC = 0x46555A5A             # "FUZZ" - shared memory magic number
FUZZ_MAX_INSTRUCTIONS = 16          # 🔥 Reduced for 4K payloads
FUZZ_MAX_VARIANTS = 5               # 🔥 Reduced to keep SHM < 1MB
FUZZ_INSTRUCTION_DATA = 4096         # 🔥 Expanded to 4K
# Shared memory configuration - must match C-side include/rr_framework.h
# New SHM structure size:
# Header(40B) + instructions[16]*(24+4096) + variants[5]*(4+16*(24+4096))
# = 40 + 16*4120 + 5*(4+16*4120) = 40 + 65920 + 329620 = ~395KB
# Set to 1MB for ample room and page alignment
FUZZ_SHM_SIZE = 1024 * 1024

# Coverage feedback constants
COVERAGE_MAP_SIZE = 64 * 1024
FUZZ_FLAG_CAPTURE_SEED = (1 << 0)   # Flag to request seed capture

# Initialization phase filtering
# These syscalls should not be mutated during the initialization phase
# to avoid corrupting memory layout
INIT_SYSCALLS = {
    'mmap', 'brk', 'set_tid_address', 'set_robust_list', 'arch_prctl',
    'munmap', 'mprotect', 'rt_sigprocmask', 'rt_sigaction'
}

# Initialization phase threshold: skip initialization syscalls in the first N system calls
# Note: This is a heuristic value; can be auto-detected by InitPhaseDetector
INIT_PHASE_THRESHOLD = 25  # Default value (if auto-detection fails)

# ===== Mutation Type Names Mapping =====
# Maps cmd values to human-readable mutation type names (used for crash metadata)
MUTATION_TYPE_NAMES = {
    FUZZ_CMD_NONE: "NONE",
    FUZZ_CMD_MUTATE_ARG: "MUTATE_ARG",
    FUZZ_CMD_REPLACE_BUFFER: "REPLACE_BUFFER",
    FUZZ_CMD_MUTATE_FLAGS: "MUTATE_FLAGS",
    FUZZ_CMD_BOUNDARY_VALUE: "BOUNDARY_VALUE",
    FUZZ_CMD_MUTATE_AUX_BUFFER: "MUTATE_AUX_BUFFER",
    FUZZ_CMD_FLIP_BITS: "FLIP_BITS",
    FUZZ_CMD_TRUNCATE: "TRUNCATE",
    FUZZ_CMD_EXTEND: "EXTEND",
    FUZZ_CMD_INTERESTING_VALUES: "INTERESTING_VALUES",
    FUZZ_CMD_LIGHT_MUTATION: "LIGHT_MUTATION",
    FUZZ_CMD_OVERWRITE_AT_OFFSET: "OVERWRITE_AT_OFFSET",
}

def get_mutation_type_name(cmd):
    """Get a human-readable mutation type name from a cmd value"""
    return MUTATION_TYPE_NAMES.get(cmd, f"UNKNOWN_{cmd}")

# Important I/O syscalls that should always be mutated (never skipped)
# Extended list to include all critical IO operations
IMPORTANT_SYSCALLS = {
    # Network IO
    'send', 'sendto', 'sendmsg', 'sendmmsg',
    'recv', 'recvfrom', 'recvmsg', 'recvmmsg',
    # File IO - read/write
    'read', 'write', 'pread', 'pwrite', 'pread64', 'pwrite64',
    'readv', 'writev', 'preadv', 'pwritev',
    # File operations
    'open', 'openat', 'creat',
    'close', 'lseek',
    # File metadata
    'stat', 'fstat', 'lstat', 'newfstatat',
    'fstatat', 'statx',
    # Random number/entropy (critical for fuzzing)
    'getrandom', 'random',
    # Inter-process communication
    'mq_send', 'mq_receive',
}

# Primary IO syscalls - direct input/output, primary mutation targets
PRIMARY_IO_SYSCALLS = {
    # File IO - read/write
    'read', 'write', 'pread', 'pwrite', 'pread64', 'pwrite64',
    'readv', 'writev', 'preadv', 'pwritev',
    # Network IO
    'recv', 'recvfrom', 'recvmsg', 'recvmmsg',
    'send', 'sendto', 'sendmsg', 'sendmmsg',
    # Random number/entropy (critical input source)
    'getrandom',
}

# Secondary IO syscalls - file operations that affect IO behavior
SECONDARY_IO_SYSCALLS = {
    'open', 'openat', 'creat',
    'lseek',
}

# Forbidden mutation syscalls - syscalls that should not be mutated
FORBIDDEN_MUTATION_SYSCALLS = {
    # Memory management (mutation would corrupt memory layout)
    'mmap', 'munmap', 'mprotect', 'brk',
    # Threading/signals (mutation would break program execution mechanisms)
    'set_tid_address', 'set_robust_list',
    'rt_sigaction', 'rt_sigprocmask',
    'clone', 'clone3',
    # Process control (should not be mutated)
    'exit', 'exit_group',
    # File descriptor management (prone to false positives)
    'close', 'dup', 'dup2', 'dup3',
}


# ===== Validation Scores (Phase A: Relax & Rank) =====
# Used by PathFinder to rank mutations instead of binary blocking
VALIDATION_SCORE_INVALID = 0      # Absolute failure (Resource-level, Phase B)
VALIDATION_SCORE_UNKNOWN = 5      # Unknown transition (not in syscall_tree)
VALIDATION_SCORE_KNOWN = 10       # Known valid transition (in syscall_tree)
VALIDATION_SCORE_STATIC = 8       # Present in static CFG but not dynamic trace (Phase C)
