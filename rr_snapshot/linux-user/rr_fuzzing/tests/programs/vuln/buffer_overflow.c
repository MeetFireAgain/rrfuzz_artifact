#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    char buffer[32];
    char safe_buffer[64];
    int magic_value = 0x12345678;

    printf("=== Buffer Overflow Test Program ===\n");
    printf("Buffer address: %p\n", buffer);
    printf("Magic value before: 0x%x\n", magic_value);

    // Read input from stdin
    printf("Reading input (max 100 bytes)...\n");
    ssize_t n = read(STDIN_FILENO, safe_buffer, 100);

    if (n <= 0) {
        printf("No input received\n");
        return 0;
    }

    printf("Read %zd bytes\n", n);

    // Vulnerability: No bounds check before copy
    if (n < 20) {
        // Safe case
        memcpy(buffer, safe_buffer, n);
        printf("Safe copy: %d bytes\n", (int)n);
    } else if (n < 40) {
        // Potential overflow
        memcpy(buffer, safe_buffer, n);
        printf("Risky copy: %d bytes (buffer size: 32)\n", (int)n);
    } else if (n < 60) {
        // Definite overflow
        memcpy(buffer, safe_buffer, n);
        printf("Overflow: %d bytes copied to 32-byte buffer!\n", (int)n);
    } else {
        // Massive overflow - will crash
        memcpy(buffer, safe_buffer, n);
        printf("Critical overflow: %d bytes!\n", (int)n);
    }

    printf("Magic value after: 0x%x\n", magic_value);

    if (magic_value != 0x12345678) {
        printf("CORRUPTION DETECTED! Magic value corrupted: 0x%x\n", magic_value);
        // Trigger crash
        *(int*)0 = 0;
    }

    printf("Program completed normally\n");
    return 0;
}
