/**
 * RR-Fuzz Coverage Tracking Module - Implementation
 * 
 * Phase 3: Implement AFL-style coverage tracking
 */

#include "rr_coverage.h"
#include "rr_framework.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/* ================= Global Variables ================= */

rr_coverage_t *g_base_coverage = NULL;
rr_coverage_t *g_coverage = NULL;
bool g_use_cfh = false;

// Use thread-local storage for prev_pc to ensure it resets on fork
static __thread uint64_t g_prev_pc = 0;
// Flow Hash state (CFH)
static __thread uint64_t g_path_hash = 0;

/* ================= Internal Helper Functions ================= */

/**
 * Create shared memory
 */
static int create_shared_memory(const char *shm_name)
{
    char shm_path[256];
    bool use_global_shm = false;
    bool file_backed = false;
    char file_backing_path[PATH_MAX] = {0};
    
    const char *env_shm_name = getenv("RR_COVERAGE_SHM");
    if (env_shm_name && env_shm_name[0] != '\0') {
        if (strncmp(env_shm_name, "file:", 5) == 0) {
            file_backed = true;
            snprintf(file_backing_path, sizeof(file_backing_path), "%s", env_shm_name + 5);
        } else {
            snprintf(shm_path, sizeof(shm_path), "/dev/shm/%s", env_shm_name);
            use_global_shm = true;
        }
    } else {
        snprintf(shm_path, sizeof(shm_path), "/dev/shm/rr_coverage_%d", getpid());
    }

    int fd;
    if (file_backed) {
        fd = open(file_backing_path, O_RDWR | O_CREAT, 0666);
    } else if (use_global_shm) {
        fd = open(shm_path, O_RDWR | O_CREAT, 0666);
    } else {
        fd = open(shm_path, O_RDWR | O_CREAT | O_EXCL, 0666);
    }

    if (fd < 0) {
        if (errno == EEXIST && !use_global_shm) {
            fd = open(shm_path, O_RDWR);
        }
        if (fd < 0) return -1;
    }

    if (ftruncate(fd, sizeof(rr_coverage_t)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* ================= Public API Implementation ================= */

int rr_coverage_init(const char *shm_name)
{
    if (g_base_coverage) return 0;

    int fd = create_shared_memory(shm_name);
    if (fd < 0) return -1;

    g_base_coverage = (rr_coverage_t *)mmap(NULL, sizeof(rr_coverage_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (g_base_coverage == MAP_FAILED) {
        g_base_coverage = NULL;
        return -1;
    }

    g_coverage = g_base_coverage;

    /* Check if CFH is enabled */
    const char *cfh_env = getenv("RR_CFH_ENABLED");
    if (cfh_env && (strcmp(cfh_env, "1") == 0 || strcasecmp(cfh_env, "true") == 0)) {
        g_use_cfh = true;
        fprintf(stderr, "[RR-COVERAGE] Control Flow Hashing (CFH) ENABLED\n");
    }

    return 0;
}

void rr_coverage_cleanup(void)
{
    if (g_base_coverage) {
        munmap(g_base_coverage, sizeof(rr_coverage_t));
        g_base_coverage = NULL;
        g_coverage = NULL;
    }
}

void rr_coverage_enable(void)
{
    if (g_base_coverage) {
        g_base_coverage->enabled = true;
    }
}

void rr_coverage_disable(void)
{
    if (g_base_coverage) {
        g_base_coverage->enabled = false;
    }
}

bool rr_coverage_is_enabled_check(void)
{
    return rr_coverage_is_enabled();
}

void rr_coverage_reset(void)
{
    if (g_base_coverage) {
        memset(g_base_coverage->coverage_map, 0, RR_COVERAGE_MAP_SIZE);
        memset(g_base_coverage->flow_hash_map, 0, RR_FLOW_HASH_MAP_SIZE);
        g_base_coverage->unique_edges = 0;
        g_base_coverage->unique_edges = 0;
        g_base_coverage->total_edges = 0;
    }
    // Also reset local state
    g_prev_pc = 0;
    g_path_hash = 0;
}

/* RR-Fuzz: Range Filtering */
/* RR-Fuzz: Range Filtering (Linked to accel/tcg/translator.c) */
extern uint64_t g_target_start;
extern uint64_t g_target_end;

void rr_set_target_range(uint64_t start, uint64_t end)
{
    g_target_start = start;
    g_target_end = end;
    fprintf(stderr, "[RR-COVERAGE] Target range set: 0x%lx - 0x%lx\n", start, end);
}

bool rr_in_target_range(uint64_t pc)
{
    if (g_target_start == 0 || g_target_end == 0) {
        // [DEBUG] Log when we use uninitialized range
        static int warned = 0;
        if (!warned) {
            fprintf(stderr, "[RR-COVERAGE] WARNING: Target range not set (start=%lx, end=%lx), allowing all addresses\n",
                    g_target_start, g_target_end);
            warned = 1;
        }
        return true;
    }
    return (pc >= g_target_start && pc <= g_target_end);
}

/**
 * Core tracking function: Record edge coverage
 */
void rr_coverage_trace_edge(uint64_t cur_pc)
{
    if (!rr_coverage_is_enabled()) {
        return;
    }
    
    /* [CRITICAL DEBUG] Log occasionally to verify edge tracking is alive */
    static uint64_t call_count = 0;
    call_count++;
    if ((call_count % 100) == 0) {
        fprintf(stderr, "[COVERAGE-STAMP] PID=%d, calls=%lu, cur_pc=0x%lx, range=0x%lx-0x%lx\n",
                getpid(), call_count, cur_pc, g_target_start, g_target_end);
    }
    
    if (!rr_in_target_range(cur_pc)) {
        if (call_count < 10) {
             fprintf(stderr, "[COVERAGE-SKIP] PC 0x%lx outside range\n", cur_pc);
        }
        return;
    }
    
    if (call_count < 10) {
         fprintf(stderr, "[COVERAGE-HIT] PC 0x%lx INSIDE range!\n", cur_pc);
    }
    
    // Standardize PC by subtracting base address (ASLR support)
    uint64_t normalized_pc = cur_pc;
    if (g_target_start > 0 && cur_pc >= g_target_start) {
        normalized_pc = cur_pc - g_target_start;
    }
    
    // AFL-style edge hashing with normalized PC
    uint64_t edge_hash = (g_prev_pc >> 1) ^ normalized_pc;
    uint32_t idx = edge_hash % RR_COVERAGE_MAP_SIZE;
    
    uint8_t old_count = g_coverage->coverage_map[idx];
    if (old_count < 255) {
        g_coverage->coverage_map[idx]++;
    }
    
    if (old_count == 0) {
        g_coverage->unique_edges++;
        /* Log if we found a new edge in THIS process */
        if (g_rr_debug.level >= RR_DEBUG_VERBOSE) {
            fprintf(stderr, "[COVERAGE-NEW-EDGE] PID=%d, pc=0x%lx, idx=%u, unique=%lu\n",
                    getpid(), cur_pc, idx, g_coverage->unique_edges);
        }
    }
    
    g_coverage->total_edges++;
    g_prev_pc = normalized_pc;

    /* [CFH] Control Flow Hashing Update */
    if (g_use_cfh) {
        /* Rolling hash: hash = (hash << 1) | (hash >> 63) ^ pc */
        /* We use a simple bitwise rotation + XOR for speed */
        g_path_hash = (g_path_hash << 1) | (g_path_hash >> 63);
        g_path_hash ^= normalized_pc;
        
        uint32_t flow_idx = g_path_hash % RR_FLOW_HASH_MAP_SIZE;
        if (g_coverage->flow_hash_map[flow_idx] < 255) {
            g_coverage->flow_hash_map[flow_idx]++;
        }
    }
}

void rr_coverage_copy_map(uint8_t *dest)
{
    if (g_base_coverage && dest) {
        memcpy(dest, g_base_coverage->coverage_map, RR_COVERAGE_MAP_SIZE);
    }
}

uint64_t rr_coverage_get_unique_edges(void)
{
    return g_base_coverage ? g_base_coverage->unique_edges : 0;
}

uint64_t rr_coverage_get_total_edges(void)
{
    return g_base_coverage ? g_base_coverage->total_edges : 0;
}
