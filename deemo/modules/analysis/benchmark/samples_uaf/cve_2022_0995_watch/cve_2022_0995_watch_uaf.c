/**
 * CVE-2022-0995 — Linux watch_queue UAF via free in event handler
 * UAF模式: list_node_uaf
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

typedef struct Node_v_2022_0995_watch { int val; struct Node_v_2022_0995_watch *next; } Node_v_2022_0995_watch;
static Node_v_2022_0995_watch *g_head_v_2022_0995_watch;

void v_2022_0995_watch_build(void) {
    g_head_v_2022_0995_watch = (Node_v_2022_0995_watch *)malloc(sizeof(Node_v_2022_0995_watch));
    if (g_head_v_2022_0995_watch) {
        g_head_v_2022_0995_watch->val = 1;
        g_head_v_2022_0995_watch->next = (Node_v_2022_0995_watch *)malloc(sizeof(Node_v_2022_0995_watch));
        if (g_head_v_2022_0995_watch->next) {
            g_head_v_2022_0995_watch->next->val = 2; g_head_v_2022_0995_watch->next->next = NULL;
        }
    }
}

void v_2022_0995_watch_free_list(void) {
    Node_v_2022_0995_watch *cur = g_head_v_2022_0995_watch;
    while (cur) { Node_v_2022_0995_watch *tmp = cur; cur = cur->next; free(tmp); }
}

void v_2022_0995_watch_traverse(void) {
    Node_v_2022_0995_watch *cur = g_head_v_2022_0995_watch;
    while (cur) { printf("%d", cur->val); cur = cur->next; }  /* UAF */
}

int main(void) {
    printf("=== v_2022_0995_watch list node UAF ===\n");
    v_2022_0995_watch_build(); v_2022_0995_watch_free_list(); v_2022_0995_watch_traverse();
    return 0;
}

