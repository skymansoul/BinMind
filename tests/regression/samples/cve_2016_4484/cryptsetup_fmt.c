/* CVE-2016-4484 — Cryptsetup initramfs shell (format string variant)
 * 漏洞: 多次错误密码输入后cryptsetup回退到debug shell — 无认证
 * 演示: 简化版format string漏洞模式
 */
#include <stdio.h>
void vulnerable_log(char *user_input) {
    printf(user_input); /* FORMAT STRING VULNERABILITY */
}
int main(int argc, char **argv) {
    if (argc > 1) vulnerable_log(argv[1]);
    return 0;
}
