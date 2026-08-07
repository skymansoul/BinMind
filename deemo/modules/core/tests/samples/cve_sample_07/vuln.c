/* CVE-2015-0235 — GHOST: glibc gethostbyname 堆溢出
 * 真实: glibc < 2.18, __nss_hostname_digits_dots 中 realloc 后拷贝越界 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ghost_vuln(char *hostname, size_t len) {
    size_t sz = len + 8;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    buf = (char *)realloc(buf, sz - 4); /* 缩小了 4B */
    /* 漏洞: 后续拷贝仍使用旧大小 → 溢出 4B */
    memcpy(buf, hostname, sz); /* sz > 新大小 by 4 */
    printf("host: %s\n", buf);
    free(buf);
}

int main(void) {
    char name[256];
    memset(name, 'G', sizeof(name) - 1);
    name[255] = '\0';
    ghost_vuln(name, 255);
    return 0;
}
