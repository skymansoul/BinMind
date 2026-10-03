/* CVE-2023-38545 — curl SOCKS5 堆溢出。
 * 分配 len, 写入 len+32。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t len = 128;
    if (argc > 1) len = strlen(argv[1]);
    char *buf = (char *)malloc(len);
    if (!buf) return 1;
    memcpy(buf, argv[1], len + 32);       /* 恒越界 */
    free(buf);
    return 0;
}
