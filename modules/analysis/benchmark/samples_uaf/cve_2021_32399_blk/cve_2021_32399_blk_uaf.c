/**
 * CVE-2021-32399 — Linux block layer UAF via blkdev_get_by_dev race
 * UAF模式: callback_uaf
 *
 * 样本设计:
 *   精简化复现该CVE的核心UAF机制.
 *   保留原始漏洞的数据流结构: malloc→free→use.
 *   去除平台特定代码, 仅保留可静态分析的user-space等价逻辑.
 *
 * 对静态分析具有挑战性的原因:
 *   1. free和use可能在不同的执行路径上 (路径敏感)
 *   2. 指针可能通过全局变量/栈/寄存器间接到use (别名分析)
 *   3. free后可能有NULL赋值但走不到use (条件分析)
 *   4. 跨函数free→use传播 (过程间分析)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *g_ctx_v_2021_32399_blk;
static char *g_old_v_2021_32399_blk;

void v_2021_32399_blk_setup(void) {
    g_ctx_v_2021_32399_blk = (char *)malloc(256);
    if (g_ctx_v_2021_32399_blk) memset(g_ctx_v_2021_32399_blk, 'C', 256);
    g_old_v_2021_32399_blk = g_ctx_v_2021_32399_blk;  /* 保存旧引用 */
}

void v_2021_32399_blk_teardown(void) {
    free(g_ctx_v_2021_32399_blk);
    g_ctx_v_2021_32399_blk = (char *)malloc(64);  /* 重赋值g_ctx */
    /* g_old仍指向已释放内存 → UAF */
}

void v_2021_32399_blk_use_old(void) {
    if (g_old_v_2021_32399_blk) printf("%c", g_old_v_2021_32399_blk[0]);  /* UAF */
}

int main(void) {
    printf("=== v_2021_32399_blk callback UAF ===\n");
    v_2021_32399_blk_setup(); v_2021_32399_blk_teardown(); v_2021_32399_blk_use_old();
    return 0;
}

