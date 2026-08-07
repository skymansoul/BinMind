/*
 * sample_13 — struct 填充导致的隐式溢出.
 *
 * 漏洞: struct 内部有编译器插入的 padding,
 * 使用 sizeof(struct) 作为分配大小, 但通过指针算术
 * 按字段大小的倍数偏移访问 → 可能超出实际分配.
 *
 * 这是静态分析误报的常见来源: 分析器看到 ptr+offset
 * 但 offset 跨越了 padding 区域 — 实际上是合法的.
 *
 * 本样本用于测试 strided interval 的 stride 追踪:
 * 对 struct 数组的迭代, 偏移应该是 sizeof(struct) 的倍数.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char a;       /* 1 byte */
    /* 3 bytes padding */
    int b;        /* 4 bytes */
    short c;      /* 2 bytes */
    /* 2 bytes padding */
} PaddedStruct;   /* sizeof = 12 (on typical compiler) */

int main(void) {
    int n = 5;
    PaddedStruct *arr = (PaddedStruct *)malloc(n * sizeof(PaddedStruct));
    if (!arr) return 1;

    /* 安全: 按 sizeof(PaddedStruct) 的步长访问 */
    for (int i = 0; i < n; i++) {
        arr[i].a = 'A' + i;
        arr[i].b = i * 100;
        arr[i].c = (short)(i * 10);
    }

    /* 危险: 按 sizeof(int) 步长访问 (stride 错误) */
    int *bad_ptr = (int *)arr;
    for (int i = 0; i < 20; i++) {
        bad_ptr[i] = i;  /* 20 ints = 80 bytes > 5*12=60 bytes → overflow! */
    }

    printf("arr[0].a = %c\n", arr[0].a);
    free(arr);
    return 0;
}
