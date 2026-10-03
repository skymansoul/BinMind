/* size 受约束的安全堆操作 (非漏洞 — 测试 size constraint 过滤)
 *
 * 场景: malloc(sz) 的返回值用于 memcpy, size 字段来自外部但被约束:
 * sz = read_input(); if (sz > 256) sz = 256; buf = malloc(sz); memcpy(buf, src, sz);
 *
 * 这是 size_constraint_inferrer 的典型用例。
 * 现有代码中 90% 的误报源于这类模式。
 *
 * 测试目标: 区间约束链 (sz: [0,∞) → [0,256]) 应证明 memcpy 安全。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 256

struct packet {
    unsigned int declared_size;
    char payload[MAX_BUF];
};

static int process_packet(const struct packet *pkt) {
    unsigned int sz;
    char *buf;

    sz = pkt->declared_size;

    /* 约束: sz ∈ [0, MAX_BUF] */
    if (sz > MAX_BUF)
        sz = MAX_BUF;

    buf = (char *)malloc(sz);
    if (!buf) return -1;

    /* SAFE: sz 已被约束, 不会超过分配大小 */
    memcpy(buf, pkt->payload, sz);

    free(buf);
    return 0;
}

int main(void) {
    struct packet pkt;
    pkt.declared_size = 100;  /* 被约束到 MAX_BUF 以下 → 安全 */
    memset(pkt.payload, 'P', sizeof(pkt.payload));
    process_packet(&pkt);
    return 0;
}
