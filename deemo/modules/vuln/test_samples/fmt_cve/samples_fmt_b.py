# coding: utf-8
#
"""格式化字符串 VULN 样本数据. 仅数据, 无逻辑."""

SAMPLES_FMT_B = [
    {
        "id": "fmt_07_printf_read",
        "cve": "None (synthetic)",
        "title": "Format string from read buffer",
        "pattern": "read(fd, buf, n); printf(buf)",
        "trigger": "网络/文件输入作格式串",
        "why": "槽缓冲区被 read 写入 → TAINT",
        "code": r'''/* fmt_07_printf_read — read 缓冲作格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[256];
    int n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) return 0;
    buf[n] = 0;
    printf(buf);
    return 0;
}
''',
    },
    {
        "id": "fmt_08_snprintf_fmtarg",
        "cve": "None (synthetic)",
        "title": "snprintf with user format",
        "pattern": "snprintf(dst, n, user_fmt, ...)",
        "trigger": "fmt 参数 (arg2=r8) 用户可控",
        "why": "fmt 溯源到 argv (arg2 寄存器) → TAINT",
        "code": r'''/* fmt_08_snprintf_fmtarg — snprintf 用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    char dst[256];
    snprintf(dst, sizeof(dst), argv[1], 7);
    puts(dst);
    return 0;
}
''',
    },
    {
        "id": "fmt_09_printf_heap_fmt",
        "cve": "None (synthetic)",
        "title": "Format string built on heap from user input",
        "pattern": "fmt=malloc+strcpy(argv[1]); printf(fmt)",
        "trigger": "堆缓冲拼装用户输入后作格式串",
        "why": "fmt 堆指针 → 非栈帧内存加载 → TAINT",
        "code": r'''/* fmt_09_printf_heap_fmt — 堆缓冲用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    char *fmt = (char *)malloc(strlen(argv[1]) + 1);
    if (!fmt) return 1;
    strcpy(fmt, argv[1]);
    printf(fmt);                  /* heap format string */
    free(fmt);
    return 0;
}
''',
    },
    {
        "id": "fmt_10_printf_scanf",
        "cve": "None (synthetic)",
        "title": "Format string from scanf buffer",
        "pattern": "scanf(\"%s\", buf); printf(buf)",
        "trigger": "scanf 输入作格式串",
        "why": "槽缓冲区被 scanf 写入 → TAINT",
        "code": r'''/* fmt_10_printf_scanf — scanf 缓冲作格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(void) {
    char buf[128];
    if (scanf("%127s", buf) != 1) return 0;
    printf(buf);
    return 0;
}
''',
    },
    {
        "id": "fmt_11_vprintf_user",
        "cve": "None (synthetic)",
        "title": "vprintf with user format",
        "pattern": "vprintf(user_fmt, ap)",
        "trigger": "vprintf fmt 参数用户可控",
        "why": "fmt 溯源到 argv → TAINT",
        "code": r'''/* fmt_11_vprintf_user — vprintf 用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>
#include <stdarg.h>

static void p(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    p(argv[1]);
    return 0;
}
''',
    },
    {
        "id": "fmt_12_printf_strcpy",
        "cve": "None (synthetic)",
        "title": "Format string via strcpy of argv",
        "pattern": "strcpy(buf, argv[1]); printf(buf)",
        "trigger": "argv 复制到栈缓冲后作格式串",
        "why": "槽缓冲被 argv 写入 (非栈帧加载) → TAINT",
        "code": r'''/* fmt_12_printf_strcpy — strcpy 复制的用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    char buf[256];
    strcpy(buf, argv[1]);
    printf(buf);
    return 0;
}
''',
    },
]
