/**
 * RR-Fuzz Unified Configuration Management System
 * Replaces scattered getenv() calls with a unified configuration interface.
 */

#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "rr_framework.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

/* Global configuration instance */
rr_config_t g_rr_config = {0};

/**
 * Default Configuration Values
 */
static const rr_config_t DEFAULT_CONFIG = {
    .enabled = false,
    .mode = RR_MODE_DISABLED,
    .trace_file = NULL,
    .shared_memory_name = NULL,
    .cmd_pipe_path = NULL,
    .status_pipe_path = NULL,
    .config_file = NULL,
    .fork_server_enabled = false,
    .fork_point = 0,
    .fork_strategy = RR_FORK_STRATEGY_AGGRESSIVE,
    .fork_fallback_threshold = 20,
    .shared_memory_size = 128 * 1024,
    .ipc_timeout = 1000,
    .use_legacy_capture = false
};

static rr_mode_t parse_mode(const char *mode_str)
{
    if (!mode_str) return RR_MODE_RECORD;
    if (strcmp(mode_str, "record") == 0) return RR_MODE_RECORD;
    if (strcmp(mode_str, "replay") == 0) return RR_MODE_REPLAY;
    if (strcmp(mode_str, "fuzzing") == 0) return RR_MODE_FUZZING;
    if (strcmp(mode_str, "disabled") == 0) return RR_MODE_DISABLED;
    if (strcasecmp(mode_str, "replay_advance") == 0) return RR_MODE_REPLAY_ADVANCE;
    return RR_MODE_RECORD;
}

static bool parse_bool(const char *str, bool default_val)
{
    if (!str) return default_val;
    if (strcmp(str, "1") == 0 || strcasecmp(str, "true") == 0 ||
        strcasecmp(str, "yes") == 0 || strcasecmp(str, "on") == 0) return true;
    return false;
}

static int parse_int(const char *str, int default_val)
{
    if (!str) return default_val;
    char *endptr;
    int val = (int)strtol(str, &endptr, 10);
    return (*endptr == '\0') ? val : default_val;
}

static size_t parse_size(const char *str, size_t default_val)
{
    if (!str) return default_val;
    char *endptr;
    unsigned long val = strtoul(str, &endptr, 10);
    if (endptr != str) {
        switch (*endptr) {
            case 'K': case 'k': val *= 1024; break;
            case 'M': case 'm': val *= 1024 * 1024; break;
            case 'G': case 'g': val *= 1024 * 1024 * 1024; break;
        }
    }
    return (size_t)val;
}

static char *expand_path(const char *path) {
    if (!path) return NULL;
    if (strstr(path, "%p")) {
        char *expanded = g_malloc0(1024);
        char pid_str[16];
        snprintf(pid_str, sizeof(pid_str), "%d", getpid());
        
        const char *p = path;
        char *dest = expanded;
        while (*p && (dest - expanded) < 1000) {
            if (*p == '%' && *(p+1) == 'p') {
                strcpy(dest, pid_str);
                dest += strlen(pid_str);
                p += 2;
            } else {
                *dest++ = *p++;
            }
        }
        *dest = '\0';
        return expanded;
    }
    return g_strdup(path);
}

int rr_config_init(void)
{
    static bool initialized = false;
    if (initialized) return 0;
    initialized = true;

    g_rr_config = DEFAULT_CONFIG;

    const char *mode_str = getenv("RR_MODE");
    if (mode_str) {
        g_rr_config.mode = parse_mode(mode_str);
        if (g_rr_config.mode != RR_MODE_DISABLED) g_rr_config.enabled = true;
    }
    
    const char *rr_enabled = getenv("RR_ENABLED");
    if (rr_enabled) g_rr_config.enabled = parse_bool(rr_enabled, g_rr_config.enabled);

    if (!g_rr_config.enabled) return 0;

    g_rr_config.trace_file = expand_path(getenv("RR_TRACE_FILE"));
    if (!g_rr_config.trace_file) g_rr_config.trace_file = expand_path("/tmp/trace_%p.dat");

    const char *shm_name = getenv("RR_SHARED_MEMORY");
    g_rr_config.shared_memory_name = g_strdup(shm_name ? shm_name : "rr_fuzzing_shm");

    g_rr_config.cmd_pipe_path = expand_path(getenv("RR_CMD_PIPE"));
    if (!g_rr_config.cmd_pipe_path) g_rr_config.cmd_pipe_path = expand_path("/tmp/rr_cmd_pipe_%p");

    g_rr_config.status_pipe_path = expand_path(getenv("RR_STATUS_PIPE"));
    if (!g_rr_config.status_pipe_path) g_rr_config.status_pipe_path = expand_path("/tmp/rr_status_pipe_%p");

    g_rr_config.fork_point = (uint32_t)parse_int(getenv("RR_FORK_POINT"), 0);
    g_rr_config.fork_server_enabled = (g_rr_config.fork_point > 0);
    
    if (g_rr_config.mode == RR_MODE_FUZZING && !getenv("RR_DISABLE_FORK_SERVER")) {
        g_rr_config.fork_server_enabled = true;
    }

    g_rr_config.shared_memory_size = parse_size(getenv("RR_SHARED_MEMORY_SIZE"), DEFAULT_CONFIG.shared_memory_size);
    g_rr_config.ipc_timeout = parse_int(getenv("RR_IPC_TIMEOUT"), DEFAULT_CONFIG.ipc_timeout);
    g_rr_config.fork_strategy = parse_int(getenv("RR_FORK_STRATEGY"), DEFAULT_CONFIG.fork_strategy);
    g_rr_config.fork_fallback_threshold = parse_int(getenv("RR_FORK_THRESHOLD"), DEFAULT_CONFIG.fork_fallback_threshold);
    g_rr_config.use_legacy_capture = parse_bool(getenv("RR_USE_LEGACY_CAPTURE"), DEFAULT_CONFIG.use_legacy_capture);

    return 0;
}

const char *rr_config_get_mode_name(rr_mode_t mode)
{
    switch (mode) {
        case RR_MODE_DISABLED: return "DISABLED";
        case RR_MODE_RECORD:   return "RECORD";
        case RR_MODE_REPLAY:   return "REPLAY";
        case RR_MODE_FUZZING:  return "FUZZING";
        case RR_MODE_REPLAY_ADVANCE: return "REPLAY_ADVANCE";
        default:               return "UNKNOWN";
    }
}

void rr_config_print(void)
{
    if (!g_rr_config.enabled) return;
    RR_INFO("=== RR-Fuzz Configuration ===");
    RR_INFO("  Mode: %s", rr_config_get_mode_name(g_rr_config.mode));
    RR_INFO("  Trace file: %s", g_rr_config.trace_file);
    RR_INFO("  Fork Server: %s", g_rr_config.fork_server_enabled ? "YES" : "NO");
    RR_INFO("=============================");
}

void rr_config_cleanup(void)
{
    g_free(g_rr_config.trace_file);
    g_free(g_rr_config.shared_memory_name);
    g_free(g_rr_config.cmd_pipe_path);
    g_free(g_rr_config.status_pipe_path);
    g_free(g_rr_config.config_file);
    memset(&g_rr_config, 0, sizeof(g_rr_config));
}
