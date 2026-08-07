/*
 * sample_fmt_03 — Format string with guard (误报测试).
 *
 * 用户输入在受保护路径中: if(fmt!=NULL) printf(fmt).
 * CWE-134: Use of Externally-Controlled Format String.
 *
 * 三阶段验证预期: is_cwe134=False, confidence=0.20
 *   Phase 1 (常量折叠): fmt来自argv, 不是常量 → 失败
 *   Phase 2 (污点追踪): argv是用户输入源 → 成功
 *   Phase 3 (路径守卫): if(fmt)守卫 → 降低置信度
 */

#include <stdio.h>
#include <string.h>

void log_message(const char *fmt, const char *arg) {
    if (fmt != NULL) {
        /* 有NULL检查守卫, 但仍可能被绕过 */
        printf(fmt, arg);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <message>\n", argv[0]);
        return 1;
    }

    log_message(argv[1], "test");
    return 0;
}
