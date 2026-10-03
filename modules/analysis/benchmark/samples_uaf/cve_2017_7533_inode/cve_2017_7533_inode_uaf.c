/**
 * CVE-2017-7533 — Linux kernel inode->i_cdev UAF via race in __inode_add
 * UAF模式: aliased_ptr_uaf
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

static char *g_ptr_v_2017_7533_inode;

void v_2017_7533_inode_run(void) {
    char *p = (char *)malloc(256);
    char *alias = p;
    g_ptr_v_2017_7533_inode = p;
    memset(p, 0, 256);
    free(alias);       /* 通过别名释放 */
    if (p) printf("%c", p[0]);  /* UAF: p是悬垂指针 */
}

int main(void) {
    printf("=== v_2017_7533_inode aliased UAF test ===\n");
    v_2017_7533_inode_run();
    return 0;
}

