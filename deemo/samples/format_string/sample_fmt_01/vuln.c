/*
 * sample_fmt_01 — 基础格式字符串漏洞 (CWE-134)
 * 模式: fgets → printf(user_input)  — 经典fmt vuln
 * 期望: CONFIRMED (置信度≥0.60)
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    printf(buf);  /* [VULN] 用户输入直接作为格式字符串 */
    return 0;
}
