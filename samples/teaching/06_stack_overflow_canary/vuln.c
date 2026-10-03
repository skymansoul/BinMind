/*
 * 教学样本 #6: 栈溢出 + Canary 泄露
 *
 * 漏洞: gets(buf) 导致栈溢出，但 Canary 保护开启。
 *       需要先通过 printf 泄露 canary 值，再构造 payload。
 * 编译: gcc -fstack-protector -no-pie -o vuln vuln.c
 * 保护: NX✓ PIE✗ Canary✓ Partial RELRO
 *
 * 利用思路: printf 泄露 canary → 溢出时保留 canary → ret2libc
 */

#include <stdio.h>
#include <unistd.h>

void vuln() {
    char buf[64];
    puts("Enter input:");
    gets(buf);
    printf("You said: ");
    printf(buf);       /* 格式化字符串泄露 canary */
    puts("");
    puts("Enter more:");
    gets(buf);         /* 栈溢出——需保留 canary */
}

int main() {
    vuln();
    return 0;
}
