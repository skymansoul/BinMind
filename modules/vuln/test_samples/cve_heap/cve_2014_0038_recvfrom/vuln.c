/* CVE-2014-0038 — recvfrom 整数下溢导致堆溢出 (kernel AF_PACKET)。
 * 分配 user_len, 写入 user_len-8; user_len<8 时下溢为巨大值。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t user_len = 64;
    if (argc > 1) user_len = strlen(argv[1]);
    char *buf = (char *)malloc(user_len);
    if (!buf) return 1;
    size_t m = user_len - 8;              /* 下溢点 */
    memcpy(buf, argv[2], m);              /* 越界写入 */
    free(buf);
    return 0;
}
