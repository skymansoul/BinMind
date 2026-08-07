/*
 * CVE-2017-18017 — Linux kernel netfilter xt_TCPMSS 堆溢出 (简化复现)
 * Linux kernel < 4.11, netfilter TCPMSS 目标模块对 TCP 选项长度验证不足.
 *
 * 漏洞机制:
 *   在 tcpmss_mangle_packet() 中, 从 skb 中解析 TCP 选项时,
 *   遍历循环 `while (optlen > 0)` 依赖 optlen 递减.
 *   若 TCP 选项长度字段被篡改为小值 (< 真实长度),
 *   循环提前终止, 但后续 memmove 使用原始计算的 tcphoff 偏移,
 *   导致越界写入/读取.
 *
 * 本文件简化: TCP选项长度解析的 defrag/rewrite 逻辑,
 *             陷阱是 optlen 递减逻辑可被恶意数据欺骗.
 *
 * 影响: 远程 DoS, 潜在的远程代码执行 (需内核内存布局信息).
 * 修复: 添加 optlen 下界检查.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* 模拟 TCP 数据包缓冲区 (简化) */
typedef struct {
    uint8_t  *data;
    size_t    len;
    size_t    tcph_off;   /* TCP 头部偏移 */
} SkBuff;

/* 漏洞函数: 遍历 TCP 选项并修改 MSS */
int tcpmss_mangle_packet(SkBuff *skb, uint16_t new_mss) {
    uint8_t *tcp_hdr = skb->data + skb->tcph_off;
    size_t    optlen = skb->len - skb->tcph_off - 20; /* TCP头部固定20字节 */
    uint8_t  *opt    = tcp_hdr + 20;

    /*
     * 漏洞: 遍历TCP选项
     *   while (optlen > 0) {
     *       if (*opt == TCPOPT_MSS) {
     *           // mangle MSS value
     *       }
     *       optlen -= op_len;   攻击者可控制 op_len
     *       opt    += op_len;
     *   }
     *
     *   若 op_len 被设为小值 (如 opts[1]=1), 但实际选项很长,
     *   optlen 递减不足, 导致 opt 指针超出合法范围.
     *   更关键的: 若 op_len 导致 optlen 回绕 (int underflow),
     *   循环永续或后续运算基于错误的 optlen.
     */

    uint8_t *work_buf = (uint8_t *)malloc(skb->len);
    if (!work_buf) return -1;

    /* 拷贝原始数据 */
    memcpy(work_buf, skb->data, skb->len);

    /*
     * 修改 MSS 值 (在 TCP 选项中的偏移)
     * 关键漏洞: optlen 计算可能因恶意 TCP 选项头而错误,
     *          导致 write_offset 超出 work_buf 范围.
     */
    size_t mss_offset = skb->tcph_off + 20 + 2; /* TCPOPT_MSS + len + value */
    if (mss_offset + 2 > skb->len) {
        /* 偏移计算错误 — 但原内核代码未充分检查 */
        free(work_buf);
        return -1;
    }

    /* 写入新的 MSS 值 */
    memcpy(work_buf + mss_offset, &new_mss, 2);

    /*
     * memmove 调整数据包大小 (移除/插入选项空间)
     * 若 optlen 计算错误, memmove 的 size 参数可能超出分配范围.
     */
    size_t move_size = skb->len - (mss_offset + 2);
    memmove(work_buf + mss_offset + 2,
            work_buf + mss_offset + 4,
            move_size); /* 潜在溢出! */

    free(work_buf);
    return 0;
}

int main(void) {
    /* 构造恶意TCP数据包 */
    size_t pkt_len = 128;
    uint8_t *pkt = (uint8_t *)calloc(1, pkt_len);

    SkBuff skb = {.data = pkt, .len = pkt_len, .tcph_off = 14}; /* Eth(14) + IP(20) */

    printf("[*] Netfilter TCPMSS mangle test (CVE-2017-18017)\n");
    printf("  skb->len=%zu, tcph_off=%zu\n", skb.len, skb.tcph_off);

    tcpmss_mangle_packet(&skb, 0x05B4); /* new MSS = 1460 */
    printf("[!] Packet mangled (potential overflow)\n");

    free(pkt);
    return 0;
}
