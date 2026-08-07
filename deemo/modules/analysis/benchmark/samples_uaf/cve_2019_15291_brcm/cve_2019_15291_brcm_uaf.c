/**
 * CVE-2019-15291 — Broadcom WiFi driver UAF via cfg80211_scan_done
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

static char *g_h_v_2019_15291_brcm;

void v_2019_15291_brcm_init(void) {
    g_h_v_2019_15291_brcm = (char *)malloc(256);
    if (g_h_v_2019_15291_brcm) memset(g_h_v_2019_15291_brcm, 0, 256);
}

void v_2019_15291_brcm_release(void) {
    free(g_h_v_2019_15291_brcm);
    /* 不置NULL: 模拟原CVE中释放后残留悬垂指针 */
}

void v_2019_15291_brcm_use(void) {
    printf("%c", g_h_v_2019_15291_brcm[0]);  /* UAF: release已释放但未置NULL */
}

int main(void) {
    printf("=== v_2019_15291_brcm cross-function UAF ===\n");
    v_2019_15291_brcm_init(); v_2019_15291_brcm_release(); v_2019_15291_brcm_use();
    return 0;
}

