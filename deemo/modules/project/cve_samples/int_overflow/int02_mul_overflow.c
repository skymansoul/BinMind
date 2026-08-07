// int02_mul_overflow: 乘法溢出导致分配过小
// 模式: count * elem_size 溢出 → malloc(sizeof(T)*count) 分配过小
// 预期检测: Mode 2 (UMUL_OVF) + Mode 7 (ALLOC_SIZE_MUL) — CRITICAL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char data[64]; } record_t;

int main(int argc, char **argv) {
    unsigned int count = 0x04000001; // 67M+1
    if (argc > 1) count = (unsigned int)atoi(argv[1]);

    // 漏洞: sizeof(record_t) * count 可能溢出
    // sizeof(record_t)=64=0x40, count=0x04000001
    // 0x40 * 0x04000001 = 0x10000040 > UINT32_MAX → 截断为 0x40
    size_t alloc_size = sizeof(record_t) * count;
    record_t *records = (record_t *)malloc(alloc_size);
    if (!records) return 1;

    // 分配仅0x40字节, 但count=0x04000001 → 循环写入越界
    for (unsigned int i = 0; i < count; i++) {
        memset(records[i].data, 'A', sizeof(records[i].data));
    }
    free(records);
    return 0;
}
