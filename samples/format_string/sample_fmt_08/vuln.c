/*
 * sample_fmt_08 — fgets→printf, 可注入 %n %x
 * 模式: fgets → printf(buf)  — 可包含 %n(任意写) %x(信息泄露)
 * 期望: CONFIRMED (has_percent_n, has_percent_x)
 */
#include <stdio.h>

int main(void) {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    /* 攻击者输入: "AAAA%x%x%x%n" — 泄露栈+任意写 */
    printf(buf);  /* [VULN] */
    return 0;
}
