/**
 * RR-Fuzz Vulnerable Test Program v2.0
 *
 * Design goals:
 * 1. Use read() system call to receive input (mutable by RR-Fuzz)
 * 2. Include multiple vulnerability types (buffer overflow, integer overflow, format string)
 * 3. Easy to trigger crashes
 * 4. Suitable for demonstrating RR-Fuzz capabilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// ============================================================
// Vulnerability 1: Classic Buffer Overflow
// ============================================================
void vuln_buffer_overflow(const char *input, size_t len) {
    char buffer[16];  // Small buffer

    // Vulnerability: no bounds check
    if (len > 0) {
        memcpy(buffer, input, len);  // Overflow when len > 16
        buffer[15] = '\0';  // Attempt to terminate (but may already have overflowed)
        printf("[VULN1] Copied %zu bytes to 16-byte buffer\n", len);
    }
}

// ============================================================
// Vulnerability 2: Length-based Overflow
// ============================================================
void vuln_length_based(const char *input, uint32_t len) {
    char buffer[32];

    // Vulnerability: trusts user-supplied length
    if (len > 0 && len < 1000) {  // Weak check
        memcpy(buffer, input, len);  // Overflow when len > 32
        printf("[VULN2] Processed %u bytes\n", len);
    }
}

// ============================================================
// Vulnerability 3: Off-by-one Error
// ============================================================
void vuln_off_by_one(const char *input, size_t len) {
    char buffer[20];
    size_t i;

    // Vulnerability: loop boundary error
    for (i = 0; i <= len && i < sizeof(buffer); i++) {  // <= should be <
        buffer[i] = input[i];
    }

    printf("[VULN3] Copied with off-by-one\n");
}

// ============================================================
// Vulnerability 4: Buffer Overflow via Integer Overflow
// ============================================================
void vuln_integer_overflow(const char *input, uint32_t count, uint32_t size) {
    char buffer[64];
    uint32_t total;

    // Vulnerability: insufficient integer overflow check
    total = count * size;  // May overflow

    if (total < sizeof(buffer)) {  // Check may be bypassed
        memcpy(buffer, input, total);
        printf("[VULN4] Copied %u bytes (count=%u, size=%u)\n", total, count, size);
    }
}

// ============================================================
// Vulnerability 5: Stack Overflow (Deep Recursion)
// ============================================================
int vuln_stack_overflow(const char *input, int depth) {
    char local_buffer[256];

    // Vulnerability: recursion depth controlled by input
    if (depth > 0 && depth < 10000) {  // Weak check
        memset(local_buffer, 'A', sizeof(local_buffer));
        return vuln_stack_overflow(input, depth - 1) + 1;
    }
    return 0;
}

// ============================================================
// Main function: select vulnerability type based on input
// ============================================================
int main() {
    unsigned char input[1024];
    ssize_t nread;
    uint32_t len_param, count_param, size_param;
    int depth_param;

    printf("═══════════════════════════════════════════════════════\n");
    printf("    RR-Fuzz Vulnerable Test Program v2.0\n");
    printf("═══════════════════════════════════════════════════════\n\n");

    // Read input from stdin - RR-Fuzz can mutate this system call!
    printf("[*] Reading input from stdin...\n");
    nread = read(STDIN_FILENO, input, sizeof(input));

    if (nread < 0) {
        perror("read");
        return 1;
    }

    if (nread == 0) {
        printf("[!] No input received (EOF)\n");
        return 0;
    }

    printf("[+] Received %zd bytes of input\n", nread);

    // Ensure null terminator
    if (nread < sizeof(input)) {
        input[nread] = '\0';
    }

    // Select vulnerability type based on the first byte of input
    if (nread >= 1) {
        unsigned char vuln_type = input[0];

        printf("[*] Vulnerability type: %d\n", vuln_type);

        switch (vuln_type % 5) {
            case 0:
                // Vulnerability 1: Simple buffer overflow
                printf("\n[TEST] Testing buffer overflow...\n");
                if (nread > 1) {
                    vuln_buffer_overflow((char*)&input[1], nread - 1);
                }
                break;

            case 1:
                // Vulnerability 2: Length-based overflow
                printf("\n[TEST] Testing length-based overflow...\n");
                if (nread >= 5) {
                    len_param = *(uint32_t*)&input[1];
                    printf("[*] Length parameter: %u\n", len_param);
                    vuln_length_based((char*)&input[5], len_param);
                }
                break;

            case 2:
                // Vulnerability 3: Off-by-one
                printf("\n[TEST] Testing off-by-one...\n");
                if (nread > 1) {
                    vuln_off_by_one((char*)&input[1], nread - 1);
                }
                break;

            case 3:
                // Vulnerability 4: Integer overflow
                printf("\n[TEST] Testing integer overflow...\n");
                if (nread >= 9) {
                    count_param = *(uint32_t*)&input[1];
                    size_param = *(uint32_t*)&input[5];
                    printf("[*] Count: %u, Size: %u\n", count_param, size_param);
                    vuln_integer_overflow((char*)&input[9], count_param, size_param);
                }
                break;

            case 4:
                // Vulnerability 5: Stack overflow
                printf("\n[TEST] Testing stack overflow...\n");
                if (nread >= 5) {
                    depth_param = *(int*)&input[1];
                    if (depth_param < 0) depth_param = -depth_param;
                    printf("[*] Recursion depth: %d\n", depth_param);
                    vuln_stack_overflow((char*)&input[5], depth_param);
                }
                break;
        }
    }

    printf("\n[✓] Program finished normally\n");
    printf("═══════════════════════════════════════════════════════\n");

    return 0;
}
