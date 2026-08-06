/* uaf_03 — realloc缩小后使用旧指针
 * CWE-416: realloc可能原地缩小, 但逻辑上指针已失效
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
    char *p = malloc(256);
    strcpy(p, "original data");
    p = realloc(p, 16); /* 缩小——原数据部分可能丢失 */
    printf("%s\n", p);    /* 使用realloc返回值(合法) */
    free(p);
    return 0;
}
