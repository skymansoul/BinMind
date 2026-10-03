/*
 * sample_fmt_01 — User-controlled format string (真阳性).
 *
 * printf(argv[1]): 用户输入直接作为格式字符串.
 * CWE-134: Use of Externally-Controlled Format String.
 *
 * 三阶段验证预期: is_cwe134=True, confidence≥0.85
 *   Phase 1 (常量折叠): fmt_arg来自argv, 不是常量 → 失败
 *   Phase 2 (污点追踪): argv是USER_INPUT_SOURCE → 成功
 *   Phase 3 (路径守卫): 无守卫 → 确认CWE-134
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <format_string>\n", argv[0]);
        return 1;
    }

    /* 漏洞: 用户输入作为格式字符串 */
    printf(argv[1]);

    return 0;
}
