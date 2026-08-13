// int02_mul_overflow: 乘法溢出导致分配过小
// 模式: count * elem_size 溢出 → malloc(sizeof(T)*count) 分配过小
// 预期检测: Mode 2 (UMUL_OVF) + Mode 7 (ALLOC_SIZE_MUL) — CRITICAL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char data[64]; } record_t;

int main(int argc, char **argv) {
    unsigned int a = 0x100000;
    unsigned int b = a * 0x1000;
    printf("%u\n", b);
    return 0;
}
