# coding: utf-8
# 创建: 2026-05-28  |  格式串语料数据 A——VULN 样本 1-6
#
"""格式化字符串 VULN 样本数据. 仅数据, 无逻辑."""

SAMPLES_FMT_A = [
    {
        "id": "fmt_01_printf_argv",
        "cve": "None (synthetic)",
        "title": "Format string from argv",
        "pattern": "printf(argv[1])",
        "trigger": "argv[1] 含 %n/%x 即任意读写",
        "why": "fmt 参数溯源到 argv (非栈帧内存加载) → TAINT",
        "code": r'''/* fmt_01_printf_argv — argv 格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    printf(argv[1]);              /* format string from argv */
    return 0;
}
''',
    },
    {
        "id": "fmt_02_printf_gets",
        "cve": "None (synthetic)",
        "title": "Format string from gets buffer",
        "pattern": "gets(buf); printf(buf)",
        "trigger": "用户输入直接作格式串",
        "why": "槽缓冲区被输入函数 (gets) 写入 → TAINT",
        "code": r'''/* fmt_02_printf_gets — gets 缓冲作格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(void) {
    char buf[128];
    gets(buf);
    printf(buf);                  /* user-controlled format */
    return 0;
}
''',
    },
    {
        "id": "fmt_03_sprintf_fmtarg",
        "cve": "None (synthetic)",
        "title": "sprintf with user format argument",
        "pattern": "sprintf(dst, user_fmt, x)",
        "trigger": "fmt 参数 (arg1=rdx) 用户可控",
        "why": "fmt 溯源到 argv (arg1 寄存器) → TAINT",
        "code": r'''/* fmt_03_sprintf_fmtarg — sprintf 用户格式参数 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    char dst[256];
    sprintf(dst, argv[1], 42);    /* fmt = argv[1] */
    puts(dst);
    return 0;
}
''',
    },
    {
        "id": "fmt_04_fprintf_user",
        "cve": "None (synthetic)",
        "title": "fprintf with user format",
        "pattern": "fprintf(stderr, user_buf)",
        "trigger": "fmt 参数 (arg1=rdx) 用户可控",
        "why": "fmt 溯源到 argv → TAINT",
        "code": r'''/* fmt_04_fprintf_user — fprintf 用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    fprintf(stderr, argv[1]);
    return 0;
}
''',
    },
    {
        "id": "fmt_05_fprintf_stdout",
        "cve": "None (synthetic)",
        "title": "fprintf(stdout) with user format",
        "pattern": "fprintf(stdout, user_fmt)",
        "trigger": "fmt 参数 (arg1=rdx) 用户可控",
        "why": "fmt 溯源到 argv → TAINT",
        "code": r'''/* fmt_05_fprintf_stdout — fprintf(stdout) 用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    fprintf(stdout, argv[1]);     /* format = argv[1] */
    return 0;
}
''',
    },
    {
        "id": "fmt_06_printf_fgets",
        "cve": "None (synthetic)",
        "title": "Format string from fgets buffer",
        "pattern": "fgets(buf, n, stdin); printf(buf)",
        "trigger": "stdin 输入直接作格式串",
        "why": "槽缓冲区被 fgets 写入 → TAINT",
        "code": r'''/* fmt_06_printf_fgets — fgets 缓冲作格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(void) {
    char buf[128];
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    printf(buf);
    return 0;
}
''',
    },
]
