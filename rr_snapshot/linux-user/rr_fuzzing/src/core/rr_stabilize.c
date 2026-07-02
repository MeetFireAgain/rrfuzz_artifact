#include "rr_framework.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void rr_stabilize_bind(CPUArchState *env, abi_long addr_ptr, abi_long addr_len) {
    if (addr_len < sizeof(struct sockaddr_in)) return;
    
    uint8_t buf[128];
    if (cpu_memory_rw_debug(env_cpu(env), addr_ptr, buf, addr_len, 0) == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)buf;
        uint16_t family = sin->sin_family;
        
        // Handle both Little Endian and Big Endian family (MIPS BE vs ARM LE)
        if (family == 2 || family == 512 || family == 0x0200) {
            uint16_t port = ntohs(sin->sin_port);
            if (port == 80 || port == 443 || port == 8080) {
                uint16_t new_port = 8080;
                if (port == 443) new_port = 8443;
                
                sin->sin_port = htons(new_port);
                sin->sin_addr.s_addr = 0; 
                
                cpu_memory_rw_debug(env_cpu(env), addr_ptr, buf, addr_len, 1);
                RR_INFO("[STABILIZE] Redirected bind port %d -> %d and IP to 0.0.0.0", port, new_port);
            }
        }
    }
}

void rr_stabilize_chdir(CPUArchState *env, abi_long path_ptr) {
    size_t len = 0;
    uint8_t *path = rr_capture_string(env, path_ptr, &len);
    if (!path) {
        RR_VERBOSE("[STABILIZE] chdir: Could not capture path string");
        return;
    }

    RR_VERBOSE("[STABILIZE] chdir check: path='%s'", path);

    if (access((const char *)path, F_OK) != 0) {
        const char *sysroot = getenv("QEMU_LD_PREFIX");
        if (sysroot) {
            char new_path[1024];
            // Ensure we don't double slash
            if (path[0] == '/' && sysroot[strlen(sysroot)-1] == '/') {
                snprintf(new_path, sizeof(new_path), "%s%s", sysroot, path + 1);
            } else if (path[0] != '/' && sysroot[strlen(sysroot)-1] != '/') {
                snprintf(new_path, sizeof(new_path), "%s/%s", sysroot, path);
            } else {
                snprintf(new_path, sizeof(new_path), "%s%s", sysroot, path);
            }
            
            RR_VERBOSE("[STABILIZE] chdir sysroot attempt: %s", new_path);
            if (access(new_path, F_OK) == 0) {
                RR_INFO("[STABILIZE] Path %s found in sysroot at %s. Redirecting...", path, new_path);
                if (chdir(new_path) == 0) {
                    uint8_t dot[] = ".\0";
                    cpu_memory_rw_debug(env_cpu(env), path_ptr, dot, 2, 1);
                }
            }
        } else {
            RR_VERBOSE("[STABILIZE] chdir: QEMU_LD_PREFIX not set");
        }
    }
    g_free(path);
}
