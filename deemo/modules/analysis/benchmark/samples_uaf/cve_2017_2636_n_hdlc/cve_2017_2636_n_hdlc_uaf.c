/**
 * CVE-2017-2636 — Linux n_hdlc line discipline UAF via tty race
 * UAF模式: reassign_after_free_uaf
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

static char *g_ptr_v_2017_2636_n_hdlc;
static char *g_saved_v_2017_2636_n_hdlc;

void v_2017_2636_n_hdlc_alloc(void) {
    g_ptr_v_2017_2636_n_hdlc = (char *)malloc(64);
    if (g_ptr_v_2017_2636_n_hdlc) memset(g_ptr_v_2017_2636_n_hdlc, 'E', 64);
    g_saved_v_2017_2636_n_hdlc = g_ptr_v_2017_2636_n_hdlc;  /* 保存副本 */
}

void v_2017_2636_n_hdlc_free_and_reassign(void) {
    free(g_ptr_v_2017_2636_n_hdlc);
    g_ptr_v_2017_2636_n_hdlc = (char *)malloc(128);  /* 重赋值: g_ptr安全 */
    /* 但 g_saved 仍指向已释放内存 → UAF */
    if (g_ptr_v_2017_2636_n_hdlc) memset(g_ptr_v_2017_2636_n_hdlc, 'F', 128);
}

void v_2017_2636_n_hdlc_use_saved(void) {
    if (g_saved_v_2017_2636_n_hdlc)
        printf("%c", g_saved_v_2017_2636_n_hdlc[0]);  /* UAF: g_saved指向已释放内存 */
}

int main(void) {
    printf("=== v_2017_2636_n_hdlc saved-alias UAF ===\n");
    v_2017_2636_n_hdlc_alloc(); v_2017_2636_n_hdlc_free_and_reassign(); v_2017_2636_n_hdlc_use_saved();
    return 0;
}

