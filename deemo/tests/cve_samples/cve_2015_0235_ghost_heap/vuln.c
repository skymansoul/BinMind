/* CVE-2015-0235 — GHOST: glibc gethostbyname 堆溢出
 * __nss_hostname_digits_dots() 中错误的大小计算导致堆溢出.
 * 类型: heap_buffer_overflow / CWE-122
 */
#include <stdlib.h>
#include <string.h>
void ghost_vuln(char *name, int len) {
    char *buf = malloc(len);
    int needed = len + 16;
    memcpy(buf, name, needed); /* BUG: needed > len */
    free(buf);
}
int main(void) {
    char n[256]; memset(n, 'A', 256);
    ghost_vuln(n, 128); return 0;
}
