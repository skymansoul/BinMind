/*
 * 模拟 CVE-2019-9213 — mmap 映射区域零页约束绕过致堆溢出
 * 真实 CVE: Linux kernel < 5.0.4, mm/mmap.c expand_downwards
 * 漏洞: 零页保护绕过 → 用户可控写入落入内核堆区域
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int g_secret;

void process_packet(char *input, unsigned int len) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    /* 漏洞: len 可能大于 128 */
    unsigned int copy_len = (len < 256) ? len : 256; /* 检查不充分 */
    memcpy(buf, input, copy_len); /* copy_len 可达 256, buf 仅 128 */
    g_secret = (unsigned int)buf[0];
    free(buf);
}

int main(int argc, char **argv) {
    char data[256];
    memset(data, 'B', sizeof(data));
    process_packet(data, 200); /* 触发: 200 > 128 */
    return 0;
}
