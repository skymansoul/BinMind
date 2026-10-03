/*
 * sample_fmt_02 — Constant format string (误报测试).
 *
 * printf(fmt) where fmt是编译时常量.
 * CWE-134: Use of Externally-Controlled Format String.
 *
 * 三阶段验证预期: is_cwe134=False, confidence=0.05
 *   Phase 1 (常量折叠): fmt是编译时常量 "Hello %s\n" → 通过
 *   Phase 2 (污点追踪): 不需要 — Phase 1已经确认安全
 */

#include <stdio.h>

int main(void) {
    const char *fmt = "Hello %s\n";
    char name[] = "World";

    /* 安全: fmt是编译时常量, 不是用户输入 */
    printf(fmt, name);

    return 0;
}
