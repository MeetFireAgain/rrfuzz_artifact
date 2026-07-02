/* 
 * BB Trace功能测试程序
 * 用于验证基本块追踪的正确性
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int global_var = 0;

/* 测试分支：简单if-else */
void test_simple_branch(int x) {
    if (x > 10) {
        printf("Branch A: x=%d\n", x);
        global_var += x;
    } else {
        printf("Branch B: x=%d\n", x);
        global_var -= x;
    }
}

/* 测试循环：for循环 */
void test_loop(int count) {
    for (int i = 0; i < count; i++) {
        global_var += i;
    }
    printf("Loop completed: global_var=%d\n", global_var);
}

/* 测试嵌套分支 */
void test_nested_branch(int a, int b) {
    if (a > 0) {
        if (b > 0) {
            printf("Both positive\n");
        } else {
            printf("A positive, B non-positive\n");
        }
    } else {
        if (b > 0) {
            printf("A non-positive, B positive\n");
        } else {
            printf("Both non-positive\n");
        }
    }
}

/* 测试函数调用链 */
int func_c(int x) {
    return x * 3;
}

int func_b(int x) {
    return func_c(x) + 2;
}

int func_a(int x) {
    return func_b(x) + 1;
}

int main(int argc, char *argv[]) {
    printf("=== BB Trace Test Program ===\n");
    
    /* 测试1: 简单分支 */
    test_simple_branch(15);  // 走Branch A
    test_simple_branch(5);   // 走Branch B
    
    /* 测试2: 循环 */
    test_loop(5);
    
    /* 测试3: 嵌套分支 */
    test_nested_branch(1, 1);   // 左上
    test_nested_branch(1, -1);  // 左下
    test_nested_branch(-1, 1);  // 右上
    test_nested_branch(-1, -1); // 右下
    
    /* 测试4: 函数调用链 */
    int result = func_a(10);
    printf("Function chain result: %d\n", result);
    
    printf("Final global_var: %d\n", global_var);
    printf("=== Test Complete ===\n");
    
    return 0;
}

