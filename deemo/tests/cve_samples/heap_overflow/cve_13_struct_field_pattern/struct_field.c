/*
 * CVE-13: 结构体字段访问 — 潜在的FP模式
 *
 * 场景: malloc(sizeof(MyStruct)=80), 访问 struct->field_at_offset_72 (8B).
 *       偏移 72+8=80 刚好在分配边界.
 * 浅层分析: offset 72 > 64? 不对, alloc=80, offset=72 < 80 → 安全.
 *
 * 但如果浅层分析错误计算了 sizeof(MyStruct)=64, 则会误报.
 * 此题测试 struct field offset 的正确性.
 *
 * 预期: sizeof 解析正确 → alloc=80 > offset=72 → 安全 (不是溢出)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char header[32];
    char body[40];
    long tail;  // offset 72
} MyStruct;

int main(void) {
    MyStruct *s = (MyStruct *)malloc(sizeof(MyStruct));
    if (!s) return 1;

    // offset 72 < sizeof(MyStruct)=80 → 安全
    s->tail = 0x4141414141414141L;

    printf("struct field access: sizeof=%zu, tail=%lx\n",
           sizeof(MyStruct), s->tail);
    free(s);
    return 0;
}
