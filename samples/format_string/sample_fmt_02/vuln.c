/*
 * sample_fmt_02 — 安全: printf("%s", user_input)
 * 模式: fgets → printf("%s", buf)  — 安全调用
 * 期望: FILTERED (置信度≤0.10)
 */
#include <stdio.h>

int main(void) {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    printf("%s", buf);  /* [SAFE] 固定格式字符串 */
    return 0;
}
