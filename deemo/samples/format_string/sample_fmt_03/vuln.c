/*
 * sample_fmt_03 — sprintf(dst, user_input) 危险格式化
 * 模式: fgets → sprintf(buf2, user_input)
 * 期望: CONFIRMED (sprintf也可被利用)
 */
#include <stdio.h>

int main(void) {
    char buf[256];
    char dst[512];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    sprintf(dst, buf);  /* [VULN] 格式化参数来自用户输入 */
    return 0;
}
