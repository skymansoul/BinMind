/* heap_overflow_10 — 循环累积写入超chunk边界
 * CWE-122: strcat循环中累积写入
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
    char *buf = malloc(32);
    buf[0] = 0;
    for (int i = 0; i < 10; i++)
        strcat(buf, "AAAA"); /* 10*4=40 > 32 */
    free(buf);
    return 0;
}
