#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * 带有明确漏洞的测试程序
 * 用于验证RR-Fuzz的crash检测和深度优先回退机制
 */

void vulnerable_function(char *input, int len) {
    char buffer[32];  // 32字节的栈缓冲区

    printf("[VulnTest] Processing input of length %d\n", len);

    if (len > 100) {
        printf("[VulnTest] 🎯 Large input detected, triggering buffer overflow...\n");
        // 故意的缓冲区溢出
        strcpy(buffer, input);  // 没有边界检查！
        printf("[VulnTest] After strcpy (this may not print if crashed)\n");
    } else if (len > 50) {
        printf("[VulnTest] ⚠️ Medium input, potential issue...\n");
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
    } else {
        printf("[VulnTest] ✅ Small input, safe copy\n");
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
    }

    printf("[VulnTest] Buffer contains: %.30s\n", buffer);
}

int main() {
    printf("═══════════════════════════════════════════════════════\n");
    printf("    RR-Fuzz Crash Test Program v1.0\n");
    printf("═══════════════════════════════════════════════════════\n");

    printf("[VulnTest] Reading input from stdin...\n");

    char input[512];
    int bytes_read = read(STDIN_FILENO, input, sizeof(input) - 1);

    if (bytes_read < 0) {
        perror("[VulnTest] Read error");
        return 1;
    } else if (bytes_read == 0) {
        printf("[VulnTest] No input received (EOF)\n");
        return 0;
    }

    input[bytes_read] = '\0';
    printf("[VulnTest] Read %d bytes\n", bytes_read);

    // 调用有漏洞的函数
    vulnerable_function(input, bytes_read);

    printf("[VulnTest] Program completed normally\n");
    return 0;
}