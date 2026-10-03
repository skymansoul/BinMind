/*
 * CVE-2021-3609 — Linux kernel CAN BCM 竞态条件→堆溢出 (简化复现)
 * Linux kernel < 5.13-rc4, CAN BCM 协议中的竞态条件导致 UAF/堆溢出.
 *
 * 漏洞机制:
 *   can_bcm 套接字的 setsockopt() 和收发路径之间存在 TOCTOU 竞态.
 *   一个线程通过 setsockopt 修改 nframes 值,
 *   而另一个线程正在 bcm_tx_setup() 中基于旧的 nframes 值
 *   处理数据. 这导致分配的 skb 大小与实际写入大小不匹配.
 *
 * 本文件简化: 模拟竞态条件下 alloc 和 write 的不一致.
 *
 * 影响: 本地提权 (需要 CAN 接口, 但可通过用户命名空间/vcan 获取).
 * 修复: 添加适当的锁保护 nframes 一致性.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* CAN BCM 操作结构 (简化) */
typedef struct {
    int     nframes;       /* 帧数 — 可被 setsockopt 动态修改 */
    uint8_t *data;
    size_t   alloc_size;
} BcmOp;

/*
 * 漏洞函数: 模拟 bcm_tx_setup() — 基于 nframes 分配+写入
 * 如果 nframes 在 alloc 和 write 之间被修改, 则溢出.
 */
void bcm_tx_setup_vulnerable(BcmOp *op) {
    int    n     = op->nframes; /* 读取 nframes (可能已过时) */
    size_t alloc = 256 + n * 64; /* CAN帧 = 64字节 */
    op->data     = (uint8_t *)malloc(alloc);
    op->alloc_size = alloc;
    if (!op->data) return;

    /*
     * 模拟竞态窗口: 在此处, 另一个线程通过 setsockopt
     * 将 op->nframes 从 n 增大到 n*2.
     * 下面的写入使用当前的 op->nframes 而非旧的 n!
     */
    int current_n = op->nframes; /* 竞态: 可能已变为 2*n */

    size_t total_write = 256 + current_n * 64;
    printf("  alloc based on n=%d: %zu bytes\n", n, alloc);
    printf("  actual write based on n=%d: %zu bytes\n", current_n, total_write);
    if (total_write > alloc) {
        printf("  [!] RACE: write %zu > alloc %zu (overflow=%zu)\n",
               total_write, alloc, total_write - alloc);
    }

    /* 实际写入 (基于竞态后的值) */
    memset(op->data, 0, total_write); /* 溢出! */
}

int main(void) {
    BcmOp op = {.nframes = 10, .data = NULL, .alloc_size = 0};

    printf("[*] CAN BCM race condition heap overflow (CVE-2021-3609)\n");
    printf("  Initial nframes = %d\n", op.nframes);

    /* 模拟竞态: 分配时 nframes=10, 写入时 nframes=20 */
    bcm_tx_setup_vulnerable(&op); /* alloc 基于 10 */

    /* 竞态发生: nframes 在 alloc 后修改 */
    op.nframes = 20; /* 另一个线程的 setsockopt */

    /* 此处在真实漏洞中是 bcm_tx_setup 的第二阶段写入 */
    printf("[!] Race window closed — check above for overflow\n");

    free(op.data);
    return 0;
}
