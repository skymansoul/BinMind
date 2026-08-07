/* CVE-2017-1000112 — Linux kernel UDP fragmentation heap overflow (simplified)
 *
 * 漏洞触发条件: 当 UFO (UDP Fragmentation Offload) 处理大于 MTU 的包时,
 * skb_copy_and_csum_dev 被调用, 拷贝长度超过 skb->len 导致越界写。
 *
 * 为何是有效测试用例: 从用户层传入的 size 可控且无上界检查,
 * malloc(size) 后的操作假设 size 已绑定 — 但实际上没有。
 * 这是一个典型的"受污点的分配大小 → 越界写入"模式。
 *
 * 测试目标: Taint engine 应追踪 size 从用户输入到 malloc 再到 memcpy,
 * Path narrowing 应检测到 size 没有被约束条件保护。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UFO_MAX_SIZE 65536

static char g_payload[UFO_MAX_SIZE];

void vulnerable_udp_frag(unsigned int size) {
    /* size 来自用户层, 可控且可能 > UFO_MAX_SIZE */
    char *skb;

    /* 缺少对 size 的检查: if (size > UFO_MAX_SIZE) return; */
    skb = (char *)malloc(size);
    if (!skb) return;

    /* 拷贝: size 字节 → 但 skb 只分配了 size, 源数据可能更大 */
    memcpy(skb, g_payload, size * 2);  /* OFF-BY: size*2 > allocated */

    free(skb);
}

int main(int argc, char **argv) {
    unsigned int sz;
    if (argc < 2) return 1;
    sz = (unsigned int)atoi(argv[1]);
    vulnerable_udp_frag(sz);  /* 用户可控 size */
    return 0;
}
