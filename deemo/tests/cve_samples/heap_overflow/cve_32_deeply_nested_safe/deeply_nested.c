/*
 * CVE-32: 深度嵌套安全 — 多层函数调用+guard约束, 最终安全
 *
 * 模式: layer3(malloc+guard) → layer2(memcpy+guard) → layer1(写入)
 * 安全: malloc(128) n<=100, memcpy(buf+off, src, 56), off<=40
 *       usable(128)=136, write_end=off+56<=96 < 136 → SAFE
 * 需要跨函数约束传播关联3层函数的guard约束
 *
 * 对应: 类似 CVE-2020-27820 (DRM 堆溢出, 深层调用链)
 * 检测预期: 跨函数传播后 PROVEN_SAFE (或 INCONCLUSIVE 保守保留)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *layer3(int n) {
    if (n > 100) return NULL;
    return (char *)malloc(128);
}

void layer2(char *buf, int off, const char *src) {
    if (off > 40) off = 40;
    memcpy(buf + off, src, 56);
}

void layer1(int n, int off) {
    char *buf = layer3(n);
    if (!buf) return;
    char data[256];
    memset(data, 'N', sizeof(data));
    layer2(buf, off, data);
    free(buf);
}

int main(int argc, char **argv) {
    int n = 80, off = 20;
    if (argc > 1) n = atoi(argv[1]);
    if (argc > 2) off = atoi(argv[2]);
    layer1(n, off);
    printf("deeply_nested_safe done\n");
    return 0;
}
