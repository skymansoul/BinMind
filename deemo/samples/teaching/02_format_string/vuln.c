/*
 * 教学样本 #2: 格式化字符串漏洞
 *
 * 漏洞: printf(buf) 使用用户输入作为格式化字符串。
 * 编译: gcc -o vuln vuln.c
 * 保护: NX✓ PIE✓ Canary✓ Full RELRO (默认全开，演示高防护场景)
 *
 * 利用思路: 信息泄露 (%p/%x 泄露栈/PIE/libc地址) → %n 定向写入
 */

#include <stdio.h>
#include <unistd.h>

char flag[64] = "flag{test_fmtstr_12345}";

int main() {
    char buf[128];
    puts("Enter format string:");
    read(0, buf, 128);
    printf(buf);
    return 0;
}
