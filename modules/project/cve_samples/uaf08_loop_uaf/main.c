// uaf08_loop_uaf — 循环中的UAF
// CVE参考: CVE-UAF-LOOP, 模式: uaf_loop_write
// 检测目标: 循环内通过悬挂指针写入, 确保循环内的每次访问都被检测
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int *arr = (int *)malloc(100 * sizeof(int));
    if (!arr) return 1;
    for (int i = 0; i < 100; i++) arr[i] = i;
    free(arr);
    // UAF: 循环写入已释放的数组
    for (int i = 0; i < 10; i++) {
        arr[i] = 0;
    }
    printf("loop UAF: %p\n", (void *)arr);
    return 0;
}
