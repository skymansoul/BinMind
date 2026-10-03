/**
 * CVE-2021-34866 — Linux eBPF verifier UAF via bpf_map_update_elem
 * UAF模式: argument_uaf
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

static char *g_msg_v_2021_34866_ebpf;

void v_2021_34866_ebpf_log(char *msg) {
    printf("log: %c\n", msg[0]);
}

void v_2021_34866_ebpf_cleanup(char *msg) {
    free(msg);
}

void v_2021_34866_ebpf_run(void) {
    g_msg_v_2021_34866_ebpf = (char *)malloc(128);
    if (!g_msg_v_2021_34866_ebpf) return;
    memset(g_msg_v_2021_34866_ebpf, 'D', 128);
    v_2021_34866_ebpf_log(g_msg_v_2021_34866_ebpf);      /* 安全: 先使用 */
    v_2021_34866_ebpf_cleanup(g_msg_v_2021_34866_ebpf);  /* 释放 */
    v_2021_34866_ebpf_log(g_msg_v_2021_34866_ebpf);      /* UAF: 释放后传参 */
}

int main(void) {
    printf("=== v_2021_34866_ebpf argument UAF ===\n");
    v_2021_34866_ebpf_run();
    return 0;
}

