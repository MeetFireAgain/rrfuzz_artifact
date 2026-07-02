/**
 * RR-Fuzz Unified Constant Definitions
 * 
 * Purpose: Centralized management of constants to eliminate magic numbers.
 * 
 * Maintenance Rules:
 * 1. Every constant must be commented with its origin and rationale.
 * 2. Related constants should be grouped by function.
 * 3. Check all usage locations when modifying a constant.
 */

#ifndef RR_CONSTANTS_H
#define RR_CONSTANTS_H

#include <linux/limits.h>  // PATH_MAX
#include <sys/select.h>    // fd_set
#include <poll.h>          // struct pollfd
#include <sys/epoll.h>     // struct epoll_event

/* Syscall Related */

/**
 * Maximum number of syscall arguments
 * 
 * Source: x86-64 ABI Specification
 * - 6 register arguments (rdi, rsi, rdx, r10, r8, r9)
 * - 2 reserved slots for future expansion or special cases
 */
#define RR_MAX_SYSCALL_ARGS     8

/**
 * Upper limit of syscall number
 * 
 * Source: Linux kernel syscall table
 * - x86-64: currently ~450
 * - Set to 512 for future scalability
 */
#define RR_MAX_SYSCALL_NR       10000

/* File Descriptor Related */

/**
 * Starting number for user-space file descriptors
 * 
 * Source: POSIX Standard
 * - 0: stdin
 * - 1: stdout
 * - 2: stderr
 * - 3+: User file descriptors
 */
#define RR_FIRST_USER_FD        3

/**
 * Maximum range for FD checks
 * 
 * Source: Linux default soft limit (ulimit -n)
 * - Usually 1024
 * - Used to traverse and find available FDs
 */
#define RR_MAX_CHECKED_FD       1024

/* Buffer Sizes */

/**
 * Maximum length for path strings
 * 
 * Source: POSIX PATH_MAX
 * - Linux: 4096 bytes
 */
#define RR_MAX_PATH_LENGTH      PATH_MAX

/**
 * Threshold for inline buffer storage
 * 
 * Source: Memory page size
 * - Data < 4KB is stored inline
 * - Data > 4KB considered for external storage
 * Rationale: Avoid frequent small memory allocations.
 */
#define RR_MAX_BUFFER_INLINE    (4 * 1024)

/**
 * Maximum size for single recorded buffer
 * 
 * Source: Empirical analysis + performance consideration
 * - 64KB is common for network buffers
 * - Exceeding this may cause memory bloat
 * Rationale: Balance between recording completeness and memory overhead.
 */
#define RR_MAX_BUFFER_TOTAL     (64 * 1024)

/**
 * Maximum size for ioctl payload
 * 
 * Source: Kernel ioctl implementation
 * - Most ioctl commands have arguments < 4KB
 * - Some devices may exceed this, but rare
 */
#define RR_MAX_IOCTL_PAYLOAD    4096

/**
 * Maximum size for sockaddr structure
 * 
 * Source: sizeof(struct sockaddr_storage)
 * - IPv4: 16 bytes
 * - IPv6: 28 bytes
 * - sockaddr_storage: 128 bytes (accommodates all protocols)
 */
#define RR_MAX_SOCKADDR_SIZE    128

/**
 * Maximum number of iovec array elements
 * 
 * Source: Linux kernel UIO_MAXIOV
 * - Maximum number of vectors for readv/writev
 * - Defined in <linux/uio.h> as 1024
 */
#define RR_MAX_IOVEC_COUNT      1024

/**
 * Typical buffer size for getdents
 * 
 * Source: libc implementation and performance tests
 * - glibc uses 32KB buffer
 * - Sufficient for most directory reads
 */
#define RR_GETDENTS_BUF_SIZE    (32 * 1024)

/* Fuzzing Related */

/**
 * Fuzzing shared memory magic number
 * 
 * Source: ASCII "FUZZ"
 * - Used to verify shared memory format integrity
 */
#define RR_FUZZ_MAGIC           0x46555A5A

/**
 * Maximum length of fuzzing instruction queue
 * 
 * Source: Shared memory size calculation
 * - Shared memory: 64KB
 * - Header: ~40 bytes
 * - Instruction: ~270 bytes (header + data)
 * - Theoretical limit: (64KB - 40) / 270 ≈ 242
 * - Actual setting: 32 (Conservative, based on AFL mutation queue average)
 * 
 * Trade-offs:
 * - Higher: Allows more mutation instructions.
 * - Lower: Reduces complexity and increases reliability.
 */
#define RR_FUZZ_MAX_INSTRUCTIONS    16
#define RR_MAX_VARIANTS             5

/**
 * Data payload size for each fuzzing instruction
 * 
 * Source: Common payload size analysis
 * - 4096 bytes (4KB) is sufficient for:
 *   * Long payloads (GET/POST requests)
 *   * File contents
 */
#define RR_FUZZ_INSTRUCTION_DATA    4096

/**
 * Total size of fuzzing shared memory
 * 
 * Source: Calculated based on Header + (Instructions × Instruction Size)
 * - Must be synchronized with the Python side
 *
 * Update triggers:
 * - conductor/constants.py: FUZZ_SHM_SIZE
 * - config/template/rr_config.fuzzing.template
 *
 * Note: Increased to 128KB to accommodate FuzzSharedMemory structure.
 */
#define RR_FUZZ_SHM_SIZE        (1024 * 1024)

/**
 * Threshold for syscalls during initialization phase
 *
 * Source: Empirical value (heuristic)
 * - Most initializations (mmap, brk, dynamic linking, etc.) happen within the first 25 syscalls.
 *
 * Note: Currently a static limit. Future implementation should be adaptive.
 */
#define RR_INIT_PHASE_THRESHOLD     25

/* Mapping Management */

/**
 * Number of hash table buckets for FD mapping
 * 
 * Source: Performance testing
 * - Assuming < 100 simultaneous open FDs.
 * - 256 buckets provide sufficient dispersion.
 * - Power of 2 optimized for hashing.
 */
#define RR_FD_MAPPING_BUCKETS       256

/**
 * Number of hash table buckets for address mapping
 * 
 * Source: Memory mapping region estimation
 * - Typical program has 10-50 mmap regions.
 * - 128 buckets provide reasonable performance.
 */
#define RR_ADDR_MAPPING_BUCKETS     128

/* IPC Related */

/**
 * IPC operation timeout (milliseconds)
 * 
 * Source: User experience
 * - 1 second is sufficient for most IPC operations.
 */
#define RR_IPC_TIMEOUT_MS           1000

/**
 * Dynamic trace pipe buffer size
 * 
 * Source: Linux default pipe maximum
 * - fcntl(F_SETPIPE_SZ) limit is usually 1MB.
 * - Used for high-throughput real-time tracing.
 */
#define RR_DYNAMIC_TRACE_PIPE_SIZE  (1024 * 1024)

/* Coverage Tracking */

/**
 * Coverage bitmap size
 * 
 * Source: AFL standard
 * - 64KB is the default AFL bitmap size.
 * - Sufficient for recording edge coverage for most programs.
 */
#define RR_COVERAGE_BITMAP_SIZE     (64 * 1024)

/**
 * Hash seed for coverage edges
 * 
 * Source: Randomly selected prime number
 * - Used to calculate (from_pc, to_pc) → bitmap_index
 */
#define RR_COVERAGE_HASH_SEED       0x12345678

/* Debugging and Logging */

/**
 * Size for config file line buffer
 * 
 * Source: Typical config line length (< 200 bytes)
 */
#define RR_CONFIG_LINE_BUFFER       256

/**
 * Strace replay lookahead count
 * 
 * Source: Experimental tuning
 * - Number of records to search forward when a syscall mismatch occurs.
 */
#define RR_STRACE_DEFAULT_LOOKAHEAD 5

/* Performance Optimization */

/**
 * Batch flush interval for Record phase
 * 
 * Source: I/O performance optimization
 * - Flushes every 100 syscalls to reduce frequent fflush calls.
 * - Trade-off: Potential loss of last 99 records on crash.
 */
#define RR_RECORD_FLUSH_INTERVAL    100

/**
 * Fork Server Fallback threshold
 * 
 * Source: Experimental testing
 * - If more than 20 syscalls occurs after a fork point, the point choice is considered suboptimal.
 */
#define RR_FORK_FALLBACK_THRESHOLD  20

#endif /* RR_CONSTANTS_H */

