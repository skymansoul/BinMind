/* CVE-2015-0240 — Samba netlogon 参数长度错配 → memcpy 越界。
 * 分配 len, 写入 len+16。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t len = 64;
    if (argc > 1) len = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(len);
    if (!buf) return 1;
    char src[64];
    memset(src, 'B', sizeof(src));
    memcpy(buf, src, len + 16);           /* 恒越界 */
    free(buf);
    return 0;
}
