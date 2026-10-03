/* uaf_09 — 缓冲区指针在realloc后失效
 * CWE-416: 旧指针在realloc原地缩小时仍被使用
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
int main() {
    char *old = malloc(128);
    char *newp = realloc(old, 16);
    puts(old); /* old在realloc后可能失效 */
    free(newp);
    return 0;
}
