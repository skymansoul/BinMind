/*
 * CVE-27: 结构体数组溢出 — 按结构体步长访问数组, 超出分配
 *
 * 模式: malloc(sizeof(st)*4) = malloc(64), 访问 arr[8].val (offset=128)
 * 溢出: usable(64)=72, offset=8*16=128 > 72 → PROVEN_OVERFLOW
 * 常见误报: 不解析sizeof乘法, 错误计算分配大小
 *
 * 对应: 类似 CVE-2016-6187 (AppArmor 堆溢出, 结构体数组越界)
 * 检测预期: PROVEN_OVERFLOW
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int id;
    int val;
    long extra[2];
} Item;

int main(void) {
    Item *arr = (Item *)malloc(sizeof(Item) * 4);
    if (!arr) return 1;

    /* sizeof(Item)=16 on x86_64, arr[8] offset=128 > malloc(64) → overflow */
    arr[8].val = 42;

    printf("struct_array_overflow done\n");
    free(arr);
    return 0;
}
