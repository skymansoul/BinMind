/**
 * CVE-2018-7566 — ALSA sequencer ioctl race → UAF on struct snd_seq_client
 * UAF模式: conditional_free_uaf
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

static char *g_buf_v_2018_7566_alsa;

void v_2018_7566_alsa_process(int err) {
    g_buf_v_2018_7566_alsa = (char *)malloc(128);
    if (!g_buf_v_2018_7566_alsa) return;
    memset(g_buf_v_2018_7566_alsa, 'X', 128);
    if (err) {
        free(g_buf_v_2018_7566_alsa);  /* 错误路径释放但不置NULL */
        /* 不return: fallthrough到下方use构成UAF */
    }
    printf("%c", g_buf_v_2018_7566_alsa[0]);  /* UAF: err路径已释放 */
    free(g_buf_v_2018_7566_alsa); g_buf_v_2018_7566_alsa = NULL;
}

int main(void) {
    printf("=== v_2018_7566_alsa conditional free UAF ===\n");
    v_2018_7566_alsa_process(1);  /* err=1: free后fallthrough到use */
    return 0;
}

