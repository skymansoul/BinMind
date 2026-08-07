/*
 * sample_fmt_06 — 安全包装: safe_print(s) → printf("%s", s)
 * 模式: 包装函数内部使用固定格式
 * 期望: FILTERED (检测到safe_wrapper模式)
 */
#include <stdio.h>

void safe_print(const char *s) {
    printf("%s", s);  /* [SAFE] 包装内固定格式 */
}

int main(void) {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    safe_print(buf);  /* 通过安全包装调用 */
    return 0;
}
