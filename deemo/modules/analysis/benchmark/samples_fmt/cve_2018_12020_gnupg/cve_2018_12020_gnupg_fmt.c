/**
 * CVE-2018-12020 — GnuPG gpg passes sig-check result to log_printf as format
 * 模式: logwrap_fmtstr
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

void v_2018_12020_gnupg_log(char *msg) {
    fprintf(stderr, msg);  /* BUG: msg可能来自用户输入 */
}

void v_2018_12020_gnupg_process(char *input) {
    v_2018_12020_gnupg_log(input);  /* 跨函数传播 — 来源需追踪 */
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf("=== v_2018_12020_gnupg cross-func fmt test ===\n");
    v_2018_12020_gnupg_process(argv[1]);
    return 0;
}

