/* CVE-2018-1000001 — glibc realpath() off-by-one heap overflow (simplified)
 * 原始漏洞: realpath() 中 getcwd() 返回的路径拼接时差一错误.
 * 简化: PTY 名称过长导致堆缓冲区差一溢出.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *build_path(const char *prefix, const char *name) {
    size_t plen = strlen(prefix);
    size_t nlen = strlen(name);
    /* bug: +1 for '/' but forgot +1 for '\0' → off-by-one */
    size_t total = plen + 1 + nlen;
    char *path = (char *)malloc(total);
    if (!path) return NULL;
    memcpy(path, prefix, plen);
    path[plen] = '/';
    memcpy(path + plen + 1, name, nlen);
    path[total] = '\0'; /* off-by-one: writes at total, but allocated only total bytes */
    return path;
}

int main(void) {
    char *p = build_path("/very/long/prefix/path", "very_long_name_that_overflows");
    printf("%s\n", p);
    free(p);
    return 0;
}
