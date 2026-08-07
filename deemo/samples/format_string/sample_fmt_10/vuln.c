/*
 * sample_fmt_10 — 间接传递: user → snprintf → printf
 * 模式: fgets → snprintf(dst, "%s", buf) → printf(dst)
 * 期望: [VULN] — snprintf的%s原样拷贝用户输入中的%字符, printf(dst)重新解释
 * 注: snprintf("%s")不消除用户输入中的格式说明符, 后续printf(dst)构成格式串漏洞
 */
#include <stdio.h>

int main(void) {
    char buf[256];
    char dst[512];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    snprintf(dst, sizeof(dst), "%s", buf);  /* [VULN] %s透传用户输入中的% */
    printf(dst);  /* dst可能含格式说明符, 构成格式串漏洞 */
    return 0;
}
