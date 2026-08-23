/*
 * CVE-2022-25636 — Linux kernel netfilter nft_dup 堆溢出 (简化复现)
 * Linux kernel 5.4 ~ 5.17-rc3, netfilter nft_dup_netdev 和 nft_fwd_netdev
 * 中存在堆越界写入.
 *
 * 漏洞机制:
 *   nft_fwd_dup_netdev_offload() 函数中, 将网络设备的硬件地址
 *   (dev->dev_addr, 可能为设备特定长度) 拷贝到固定大小
 *   的流表动作数据结构中, 没有验证 dev_addr 长度.
 *
 * 本文件简化: 分配固定大小的动作结构体,
 *             但从设备获取的不定长的硬件地址拷贝到其中.
 *
 * 影响: 本地提权 (需要 CAP_NET_ADMIN, 但可通过用户命名空间获取).
 * 修复: 添加 dev->addr_len 验证, 限制拷贝长度.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* Netfilter 流表动作数据结构 (简化) */
typedef struct {
    uint8_t  type;
    uint8_t  mac_addr[6];   /* 仅为以太网预留6字节 */
    uint16_t flags;
} NftDupAction;

/* 模拟网络设备 */
typedef struct {
    char     name[16];
    uint8_t  dev_addr[32];  /* 某些设备有更长的硬件地址 (如 InfiniBand=20) */
    int      addr_len;      /* 实际地址长度 — 攻击者可构造为 >6 */
} NetDevice;

/*
 * 漏洞函数: nft_fwd_dup_netdev_offload
 * 将设备硬件地址拷贝到动作结构中, 但不验证长度.
 */
NftDupAction *setup_dup_action(NetDevice *dev) {
    /* 固定分配: 动作结构仅为以太网预留6字节MAC */
    NftDupAction *act = (NftDupAction *)calloc(1, sizeof(NftDupAction));
    if (!act) return NULL;

    act->type  = 0x01; /* NFTA_DUP */

    /*
     * 漏洞: 直接拷贝 dev->addr_len 字节到 act->mac_addr[6]
     *       如果 dev->addr_len > 6 (如 InfiniBand = 20),
     *       则越界写入相邻字段和内存!
     */
    size_t copy_len = (size_t)dev->addr_len;
    printf("  dev->addr_len=%d, mac_addr capacity=6\n", dev->addr_len);
    if (copy_len > sizeof(act->mac_addr)) {
        printf("  [!] copy_len(%zu) > mac_addr(%zu) — OVERFLOW!\n",
               copy_len, sizeof(act->mac_addr));
    }
    memcpy(act->mac_addr, dev->dev_addr, copy_len); /* 溢出! */

    return act;
}

int main(void) {
    NetDevice evil_dev = {
        .name = "ib0",
        .addr_len = 20,  /* InfiniBand 的硬件地址长度 — 大于6字节! */
    };
    memset(evil_dev.dev_addr, 0x42, sizeof(evil_dev.dev_addr));

    printf("[*] Netfilter nft_dup heap overflow test (CVE-2022-25636)\n");

    NftDupAction *act = setup_dup_action(&evil_dev);
    if (act) {
        printf("[!] Action created (potential overflow)\n");
        free(act);
    }
    return 0;
}
