#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-01: 经典乘法溢出 — malloc(n * size)当n*size溢出时分配不足
 * CWE-190: Integer Overflow leading to heap buffer overflow */
int main(int argc, char **argv) {
    int n;
    if (argc < 2) n = 10;
    else n = atoi(argv[1]);

    /* VULNERABLE: n*sizeof(int)可能溢出, 例如n=0x40000001 */
    int *arr = (int *)malloc(n * sizeof(int));
    if (!arr) return 1;
    for (int i = 0; i < n; i++)
        arr[i] = i;  /* 溢出时越界写入 */
    free(arr);
    return 0;
}
