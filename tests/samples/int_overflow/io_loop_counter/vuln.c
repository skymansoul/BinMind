#include <stdio.h>
#include <stdlib.h>
/* IO-06: 循环计数器溢出 — 小类型计数器回绕导致无限循环/越界 */
int main(void) {
    unsigned short i;  /* 最大65535 */
    int *buf = (int *)malloc(70000 * sizeof(int));
    if (!buf) return 1;
    for (i = 0; i < 70000; i++)  /* i永远<70000, 因为ushort最大65535 */
        buf[i] = (int)i;  /* VULNERABLE: 无限循环 + 越界 */
    free(buf); return 0;
}
