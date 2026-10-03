/* CVE-2018-1000001 — glibc realpath 堆溢出 (strcpy 无界)。
 * 分配随路径长度增长, strcpy 无界写入。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    size_t plen = strlen(argv[1]);
    char *buf = (char *)malloc(plen + 2);
    if (!buf) return 1;
    strcpy(buf, argv[1]);                 /* 无界 → 越界 */
    free(buf);
    return 0;
}
