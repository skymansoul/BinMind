/*
 * CVE-2020-14386 — Linux kernel AF_PACKET 堆溢出 (简化复现)
 * Linux kernel < 5.9-rc7, AF_PACKET 套接字的 tpacket_rcv() 中堆溢出.
 *
 * 漏洞机制:
 *   AF_PACKET 接收路径中, 计算需要分配的 skb 大小时,
 *   `tp_snaplen` (快照长度) 和实际帧长度不一致可能触发溢出.
 *   攻击者通过 PACKET_TX_RING 设置较小的 tp_snaplen,
 *   然后用大于 tp_snaplen 的实际帧数据触发额外的拷贝.
 *
 * 本文件简化: 分配大小与拷贝大小之间的竞争条件/验证不足.
 *
 * 影响: 本地提权 (从非特权用户或容器内), CAP_NET_RAW 可绕过某些限制.
 * 修复: 添加 tp_snaplen 与实际数据长度的一致性验证.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* 模拟 tpacket 接收描述符 */
typedef struct {
    uint32_t tp_snaplen;   /* 快照长度 (user可控) */
    uint32_t tp_len;       /* 实际帧长度 */
    uint8_t  *ring_buffer; /* 环形缓冲区 */
} TPaketRing;

/*
 * 漏洞函数: tpacket_rcv 的数据拷贝
 * 分配基于 tp_snaplen, 但拷贝可能基于 tp_len
 * 或帧数据的实际可用大小.
 */
int tpacket_rcv_vulnerable(TPaketRing *ring, const uint8_t *frame,
                            uint32_t frame_len) {
    /*
     * 漏洞: alloc_size 基于 tp_snaplen (小值),
     *       但 actual_copy 可能基于 frame_len (大值).
     *       如果 tp_snaplen < frame_len, 溢出!
     */
    uint32_t snaplen = ring->tp_snaplen; /* 攻击者设为小值, 如 0x10 */
    uint32_t alloc   = snaplen + 256;    /* 额外头部/元数据空间 */

    uint8_t *skb_data = (uint8_t *)malloc(alloc);
    if (!skb_data) return -1;

    /* 拷贝MAC头 + 网络层头部到skb */
    uint32_t copy_len = frame_len; /* 实际操作可能用 frame_len 而非 snaplen */
    if (copy_len > alloc) {
        /* 只有在这个分支中才发现溢出条件 —
         * 但原内核代码未充分比较 alloc 和 copy_len. */
        printf("  [!] copy_len(%u) > alloc(%u) — OVERFLOW!\n", copy_len, alloc);
    }

    memcpy(skb_data, frame, copy_len); /* 溢出! */
    free(skb_data);
    return 0;
}

int main(void) {
    TPaketRing ring = {
        .tp_snaplen = 16,        /* 攻击者设置小快照长度 */
        .tp_len     = 0x2000,    /* 但实际帧很长 */
        .ring_buffer = NULL,
    };

    uint8_t malicious_frame[0x2000];
    memset(malicious_frame, 0x41, sizeof(malicious_frame));

    printf("[*] AF_PACKET tpacket_rcv overflow test (CVE-2020-14386)\n");
    printf("  tp_snaplen=%u, frame_len=%zu\n",
           ring.tp_snaplen, sizeof(malicious_frame));

    tpacket_rcv_vulnerable(&ring, malicious_frame, sizeof(malicious_frame));
    printf("[!] tpacket_rcv completed (potential overflow)\n");
    return 0;
}
