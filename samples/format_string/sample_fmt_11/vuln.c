/*
 * sample_fmt_11 — getenv 作为格式字符串
 * 模式: getenv → printf(env_val)
 * 期望: CONFIRMED (环境变量可控)
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *lang = getenv("LANG");
    if (lang != NULL)
        printf(lang);  /* [VULN] 环境变量作为格式字符串 */
    return 0;
}
