#include <stdio.h>
#include <stdlib.h>
/* IO-01: 乘法整数溢出导致堆分配不足 */
int main(int argc, char **argv) {
    int count = argc > 1 ? atoi(argv[1]) : 1000;
    /* size_t alloc = count * sizeof(int);  若count=0x40000001, 乘积溢出 */
    size_t n = (size_t)count * sizeof(int);
    int *buf = (int *)malloc(n);
    if (!buf) { printf("malloc failed\n"); return 1; }
    for (int i = 0; i < count; i++) buf[i] = i;  /* VULNERABLE if count overflowed */
    printf("last=%d\n", buf[count-1]);
    free(buf); return 0;
}
