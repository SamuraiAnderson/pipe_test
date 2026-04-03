/**
 * @file main.c
 * @brief 测试程序主入口
 */

#include <stdio.h>
#include <stdlib.h>

/* 外部测试函数声明 */
extern int run_frame_tests(void);
extern int run_pairing_tests(void);
extern int run_comm_tests(void);
extern int run_crypto_tests(void);

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("========================================\n");
    printf("  SProtocol Library Test Suite\n");
    printf("========================================\n\n");
    
    int total_passed = 0;
    int total_failed = 0;
    
    /* 帧协议测试 */
    printf("\n[1/4] Running Frame Tests...\n");
    if (run_frame_tests() == 0) {
        total_passed++;
        printf("Frame Tests: PASSED\n");
    } else {
        total_failed++;
        printf("Frame Tests: FAILED\n");
    }
    
    /* 配对测试 */
    printf("\n[2/4] Running Pairing Tests...\n");
    if (run_pairing_tests() == 0) {
        total_passed++;
        printf("Pairing Tests: PASSED\n");
    } else {
        total_failed++;
        printf("Pairing Tests: FAILED\n");
    }
    
    /* 通信测试 */
    printf("\n[3/4] Running Communication Tests...\n");
    if (run_comm_tests() == 0) {
        total_passed++;
        printf("Communication Tests: PASSED\n");
    } else {
        total_failed++;
        printf("Communication Tests: FAILED\n");
    }
    
    /* 加密和杂项测试 */
    printf("\n[4/4] Running Crypto & Misc Tests...\n");
    if (run_crypto_tests() == 0) {
        total_passed++;
        printf("Crypto Tests: PASSED\n");
    } else {
        total_failed++;
        printf("Crypto Tests: FAILED\n");
    }
    
    /* 总结 */
    printf("\n========================================\n");
    printf("  Test Summary\n");
    printf("========================================\n");
    printf("  Total test suites: %d\n", total_passed + total_failed);
    printf("  Passed: %d\n", total_passed);
    printf("  Failed: %d\n", total_failed);
    printf("========================================\n");
    
    if (total_failed > 0) {
        printf("\nSOME TESTS FAILED!\n");
        return 1;
    }
    
    printf("\nALL TESTS PASSED!\n");
    return 0;
}
