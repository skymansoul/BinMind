#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-03: 分配大小溢出 — 用户提供的size_t在计算过程中溢出
 * CWE-680: Integer Overflow to Buffer Overflow */
size_t compute_size(int count, int elem_size) {
    return (size_t)(count * elem_size);  /* 乘法可能溢出 */
}
int main(int argc, char **argv) {
    int count, elem = 1024;
    if (argc < 2) count = 100;
    else count = atoi(argv[1]);
    size_t alloc = compute_size(count, elem);
    char *buf = (char *)malloc(alloc);
    if (!buf) return 1;
    memset(buf, 0, count * elem);  /* 原始count*elem可能溢出 */
    free(buf);
    return 0;
}
