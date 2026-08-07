/* CVE-2019-13139 — Docker `docker build` git checkout heap overflow (simplified)
 * 原始: 处理长路径名时未充分校验长度导致堆溢出.
 * 简化: getcwd + subdir 拼接, 边界检查用 <= 而非 < → off-by-one.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *join_path(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    size_t n = la + 1 + lb;
    char *p = (char *)malloc(n);
    if (!p) return NULL;
    memcpy(p, a, la); p[la] = '/'; memcpy(p+la+1, b, lb);
    p[n] = '\0'; /* off-by-one */
    return p;
}

int main(void) {
    char *p = join_path("/var/lib/docker/overlay2/abc123/diff/usr/share/nginx/html",
                        "index.html");
    printf("%s\n", p); free(p);
    return 0;
}
