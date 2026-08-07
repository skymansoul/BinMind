/**
 * CVE-2018-17182 — Linux kernel vmacache_flush_all UAF via mmap race
 * UAF模式: cross_function_uaf
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

static char *g_obj_v_2018_17182_vmac;

void v_2018_17182_vmac_cleanup(void) {
    free(g_obj_v_2018_17182_vmac);  /* 被调用者释放但不置NULL */
}

void v_2018_17182_vmac_setup(void) {
    g_obj_v_2018_17182_vmac = (char *)malloc(512);
    if (g_obj_v_2018_17182_vmac) memset(g_obj_v_2018_17182_vmac, 0, 512);
}

void v_2018_17182_vmac_process(void) {
    printf("%c", g_obj_v_2018_17182_vmac[64]);  /* UAF: cleanup已释放 */
}

int main(void) {
    printf("=== v_2018_17182_vmac cross-function UAF ===\n");
    v_2018_17182_vmac_setup(); v_2018_17182_vmac_cleanup(); v_2018_17182_vmac_process();
    return 0;
}

