/*
 * 简单Fuzzing目标 - 用于验证端到端fuzzing流程
 * 包含多个可发现的路径和一个"漏洞"
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int secret_path_1 = 0;
int secret_path_2 = 0;
int bug_triggered = 0;

void process_input(const char *input) {
    int len = strlen(input);
    
    // 路径1: 长度检查
    if (len > 10) {
        printf("[+] Path 1: Long input detected\n");
        secret_path_1 = 1;
        
        // 路径2: 特定前缀
        if (strncmp(input, "FUZZ", 4) == 0) {
            printf("[+] Path 2: FUZZ prefix found\n");
            secret_path_2 = 1;
            
            // 路径3: 特定长度
            if (len == 15) {
                printf("[+] Path 3: Perfect length!\n");
                
                // "漏洞"：特定字符串触发
                if (strcmp(input, "FUZZ_MAGIC_PWN!") == 0) {
                    bug_triggered = 1;
                    printf("\n");
                    printf("╔═══════════════════════════════════════╗\n");
                    printf("║  🐛 BUG TRIGGERED!                   ║\n");
                    printf("║  Fuzzer successfully found the path! ║\n");
                    printf("╚═══════════════════════════════════════╝\n");
                    printf("\n");
                }
            }
        }
    } else if (len > 5) {
        printf("[-] Medium input\n");
    } else {
        printf("[-] Short input\n");
    }
}

int main() {
    char input[256];
    
    printf("═══════════════════════════════════════\n");
    printf("  Simple Fuzzing Target\n");
    printf("═══════════════════════════════════════\n");
    printf("Enter input: ");
    
    if (fgets(input, sizeof(input), stdin)) {
        // 移除换行符
        input[strcspn(input, "\n")] = 0;
        
        printf("Processing: '%s' (len=%zu)\n", input, strlen(input));
        process_input(input);
    }
    
    printf("\n");
    printf("═══════════════════════════════════════\n");
    printf("Status:\n");
    printf("  Secret Path 1: %s\n", secret_path_1 ? "✓" : "✗");
    printf("  Secret Path 2: %s\n", secret_path_2 ? "✓" : "✗");
    printf("  Bug Triggered: %s\n", bug_triggered ? "🐛 YES!" : "✗");
    printf("═══════════════════════════════════════\n");
    
    return bug_triggered ? 42 : 0;
}

