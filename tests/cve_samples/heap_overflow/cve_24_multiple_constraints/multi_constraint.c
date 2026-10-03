/*
 * CVE-24: 多约束联合 — alloc_size, copy_size, offset均有约束
 *
 * 模式: malloc(n) n<=256, memcpy(buf+off, src, sz), off<=200, sz<=56
 * 安全: usable(256)=264, write_end=off+sz<=256 < 264 → SAFE
 * 需要多约束联合判定: 单独看任何一项都无法确定
 *
 * 对应: 类似 CVE-2023-6246 (syslog 堆溢出, 多变量交互)
 * 检测预期: FM边界推理联合多约束 → PROVEN_SAFE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int n = 256, off = 200, sz = 56;
    if (argc > 1) n = atoi(argv[1]);
    if (argc > 2) off = atoi(argv[2]);
    if (argc > 3) sz = atoi(argv[3]);

    if (n > 256) n = 256;
    if (off > 200) off = 200;
    if (sz > 56) sz = 56;

    char *buf = (char *)malloc(n);
    if (!buf) return 1;

    char data[256];
    memset(data, 'D', sizeof(data));
    memcpy(buf + off, data, sz);

    printf("multi_constraint: n=%d off=%d sz=%d\n", n, off, sz);
    free(buf);
    return 0;
}
