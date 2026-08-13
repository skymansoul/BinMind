/*
 * CVE-2023-34029 模式复刻 — KVM 格式化字符串
 * 真实漏洞: 内核 KVM 的调试接口对用户可控的 vCPU 名直接
 *           格式化
 * 触发条件: 虚拟机名含 % 转换符
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: KVM 调试输出 */
void kvm_debug(const char *vm_name) {
    /* 缺陷: vm_name 用户可控 */
    printf(vm_name);
}

int main(int argc, char **argv) {
    char name[64];
    if (argc > 1) {
        strncpy(name, argv[1], sizeof(name) - 1);
        name[sizeof(name) - 1] = 0;
    } else {
        strcpy(name, "vm_%x%x%x%x%x");
    }
    kvm_debug(name);
    return 0;
}
