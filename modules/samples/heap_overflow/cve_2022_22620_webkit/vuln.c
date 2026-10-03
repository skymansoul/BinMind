/*
 * CVE-2022-22620 模式复刻 — 尺寸计算缺陷型堆溢出
 * 真实漏洞: WebKit 处理恶意网页内容时的内存破坏 (RCE)
 * 触发条件: 元素数量导致总大小计算截断 (32 位乘法回绕)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct element {
    unsigned int id;
    char payload[8];
};

struct buffer {
    unsigned int count;
    struct element *elems;
};

int build_buffer(struct buffer *b, unsigned int count) {
    /* 缺陷: 32 位乘法回绕 — count*sizeof 溢出后分配过小 */
    size_t total = count * sizeof(struct element);
    b->elems = (struct element *)malloc(total);
    if (!b->elems) return -1;
    b->count = count;
    unsigned int i;
    for (i = 0; i < count; i++) {           /* 写 count 个元素 */
        b->elems[i].id = i;
        b->elems[i].payload[0] = 'A';
    }
    return 0;
}

int main(int argc, char **argv) {
    struct buffer b;
    b.count = 0;
    /* 0x40000000 * 12 = 0x300000000 → 32 位截断为 0 */
    if (build_buffer(&b, 0x40000000) == 0) {
        free(b.elems);
    }
    return 0;
}
