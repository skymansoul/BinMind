/*
 * CVE-2023-4863 模式复刻 — libwebp 大帧图像堆越界写
 * 真实漏洞: libwebp BuildHuffmanTable 对超大 Huffman 表
 *           递归展开时越界写, 经浏览器渲染链可 RCE
 * 触发条件: 图像元数据声明的 Huffman 码表大小超限
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TABLE 64

struct huffman_code {
    unsigned char symbol;
    unsigned char bits;
};

/* 复刻 BuildHuffmanTable: 按 2^bits 展开码表, 无容量检查 */
int build_table(struct huffman_code *codes, int n, char *out, int out_cap) {
    int pos = 0;
    int i;
    for (i = 0; i < n; i++) {
        int span = 1 << codes[i].bits;      /* 展开宽度 2^bits */
        if (pos + span > out_cap)           /* 有检查但有缺陷: 在写后 */
            return -1;
        int j;
        for (j = 0; j < span; j++) {
            out[pos + j] = (char)codes[i].symbol;
        }
        pos += span;
    }
    return pos;
}

int main(int argc, char **argv) {
    /* 恶意 Huffman 表: 5 个 7-bit 码 → 需 640B 展开空间 */
    struct huffman_code codes[5];
    int i;
    for (i = 0; i < 5; i++) {
        codes[i].symbol = (unsigned char)i;
        codes[i].bits = 7;
    }
    char *out = (char *)malloc(MAX_TABLE);  /* 64B 缓冲 */
    if (!out) return 1;
    int n = build_table(codes, 5, out, MAX_TABLE);
    free(out);
    (void)n;
    return 0;
}
