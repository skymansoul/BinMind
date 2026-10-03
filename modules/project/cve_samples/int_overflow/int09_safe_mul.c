// int09_safe_mul: 安全乘法 — sizeof在编译时常量范围内
// 模式: sizeof(int) * 100 — 编译器可证明安全
// 预期: 不产生finding (SAFE)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int count = 100;
    if (argc > 1) count = atoi(argv[1]);

    // 安全: sizeof(int)=4, 最大4*100=400, 不可能溢出
    if (count < 0 || count > 100) count = 100;

    size_t alloc = sizeof(int) * (unsigned)count;
    int *arr = (int *)malloc(alloc);
    if (!arr) return 1;

    for (int i = 0; i < count; i++) {
        arr[i] = i;
    }
    free(arr);
    return 0;
}
