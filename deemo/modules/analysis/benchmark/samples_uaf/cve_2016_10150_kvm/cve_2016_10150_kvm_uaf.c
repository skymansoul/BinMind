/**
 * CVE-2016-10150 — KVM kvm_vcpu_ioctl_device_add dangling pointer UAF
 * UAF模式: simple_uaf_global_ptr
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

static char *g_ptr_v_2016_10150_kvm;

void v_2016_10150_kvm_alloc(void) {
    g_ptr_v_2016_10150_kvm = (char *)malloc(256);
    if (g_ptr_v_2016_10150_kvm) memset(g_ptr_v_2016_10150_kvm, 0, 256);
}

void v_2016_10150_kvm_free(void) {
    free(g_ptr_v_2016_10150_kvm);  /* 缺少 g_ptr = NULL → UAF */
}

void v_2016_10150_kvm_use(void) {
    if (g_ptr_v_2016_10150_kvm) {
        printf("%c", g_ptr_v_2016_10150_kvm[0]);  /* UAF: free后使用 */
    }
}

int main(void) {
    printf("=== v_2016_10150_kvm UAF test ===\n");
    v_2016_10150_kvm_alloc(); v_2016_10150_kvm_free(); v_2016_10150_kvm_use();
    return 0;
}

