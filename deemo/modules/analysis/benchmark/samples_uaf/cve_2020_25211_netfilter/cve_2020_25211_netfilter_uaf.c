/**
 * CVE-2020-25211 — Linux netfilter ctnetlink UAF via conntrack delete
 * UAF模式: error_path_uaf
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

static char *g_res_v_2020_25211_netfilter;

int v_2020_25211_netfilter_allocate(void) {
    g_res_v_2020_25211_netfilter = (char *)malloc(128);
    return g_res_v_2020_25211_netfilter ? 0 : -1;
}

void v_2020_25211_netfilter_cleanup_on_error(void) {
    if (g_res_v_2020_25211_netfilter) { free(g_res_v_2020_25211_netfilter); }
}

void v_2020_25211_netfilter_use_resource(void) {
    if (g_res_v_2020_25211_netfilter) printf("%c", g_res_v_2020_25211_netfilter[0]);  /* 可能UAF */
}

int main(void) {
    printf("=== v_2020_25211_netfilter error path UAF ===\n");
    if (v_2020_25211_netfilter_allocate() == 0) {
        v_2020_25211_netfilter_cleanup_on_error();  /* 错误路径释放 */
        v_2020_25211_netfilter_use_resource();      /* 继续使用 → UAF */
    }
    return 0;
}

