/*
 * 教学样本 #1: 经典栈溢出 (gets)
 *
 * 漏洞: gets(buf) 无边界检查，输入超过 64 字节覆盖返回地址。
 * 编译: gcc -fno-stack-protector -no-pie -o vuln vuln.c
 * 保护: NX✓ PIE✗ Canary✗ (故意关闭以演示基础栈溢出)
 *
 * 利用思路: ret2libc (leak puts@GOT → compute libc base → system("/bin/sh"))
 */

#include <stdio.h>
#include <unistd.h>

void vuln() {
    char buf[64];
    puts("Enter input:");
    gets(buf);
    puts(buf);
}

int main() {
    vuln();
    return 0;
}
