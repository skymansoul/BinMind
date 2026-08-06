/* heap_overflow_03 — realloc 后写入超过新大小
 * 对应 CWE-122: realloc 缩小后仍按旧大小写入
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *p = (char *)malloc(256);
    p = (char *)realloc(p, 64);  /* 缩小到 64 */
    memset(p, 'A', 128);          /* 按旧大小 128 写入 */
    free(p);
    return 0;
}
