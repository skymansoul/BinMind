/* N/A 安全对照: 写入前显式边界检查 len<=64.
 * 预期: 检测器应识别守卫约束, 判定 BENIGN.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t len = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    if (len <= 64) {
        memcpy(buf, argv[2], len);
        printf("buf[0]=%c\n", buf[0]);
    }
    free(buf);
    return 0;
}
