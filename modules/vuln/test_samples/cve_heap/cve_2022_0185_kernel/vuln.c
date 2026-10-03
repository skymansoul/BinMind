/* CVE-2022-0185 — kernel fs_context 堆溢出 (长度错配)。
 * 分配 64, 写入 argv 长度 (可超 64)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    size_t user_len = strlen(argv[argc - 1]);
    memcpy(buf, argv[1], user_len);       /* 外部长度写入 */
    free(buf);
    return 0;
}
