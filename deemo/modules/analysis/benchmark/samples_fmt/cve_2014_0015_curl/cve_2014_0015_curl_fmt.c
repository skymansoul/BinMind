/**
 * CVE-2014-0015 — curl URL-parsed hostname passed to printf → format string injection
 * 模式: url_fmtstr
 *
 * 样本设计: 精简化复现格式字符串漏洞核心机制.
 * 对静态分析的挑战:
 *   1. 格式字符串来源需追踪 (寄存器/栈/全局/跨函数)
 *   2. 字面量格式字符串应被过滤 (误报控制)
 *   3. 跨函数传播需参数追踪
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void v_2014_0015_curl_vuln(char *user_input) {
    printf(user_input);  /* BUG: 用户输入作为格式字符串 */
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf("=== v_2014_0015_curl fmt test ===\n");
    v_2014_0015_curl_vuln(argv[1]);
    return 0;
}

