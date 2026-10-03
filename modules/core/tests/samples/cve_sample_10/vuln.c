/* 多路径堆溢出 — 两个分支中一者溢出, 一者安全
 * 测试路径敏感分析能否区分 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void multi_path(unsigned int mode, char *data) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    if (mode == 0) {
        /* 路径A: 安全 — 只写 64B */
        memcpy(buf, data, 64);
    } else {
        /* 路径B: 溢出 — 写 256B > 128B */
        memcpy(buf, data, 256);
    }
    printf("mode=%u\n", mode);
    free(buf);
}

int main(int argc, char **argv) {
    char d[256]; memset(d, 'M', sizeof(d));
    multi_path(argc > 1 ? 1 : 0, d);
    return 0;
}
