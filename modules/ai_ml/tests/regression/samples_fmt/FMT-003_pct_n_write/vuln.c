/* FMT-003: %n写入——最高风险格式串漏洞
 * 场景: printf(user_input) 且user_input含"%n" → 写任意值到栈地址
 * 检测器能力: 检测%n格式符 → CRITICAL
 * 预期: has_pct_n=True, risk=CRITICAL
 */

#include <stdio.h>
#include <string.h>

int global_counter = 0;

/* BUG: 用户可通过%n覆盖global_counter */
void unsafe_format_log(const char *user_msg) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "LOG: ");
    strncat(buffer, user_msg, sizeof(buffer) - 6);

    /* BUG: buffer包含用户输入的%n → 可能写任意值 */
    printf(buffer, &global_counter);
}

/* BUG: 直接作为格式化函数参数——含%n时更危险 */
void format_with_user_fmt(const char *fmt, int value) {
    /* %n可以写value的地址——完全可控的任意写 */
    printf(fmt, value);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        /* %n场景: ./prog "%d %n" → 写4到栈上某地址 */
        format_with_user_fmt(argv[1], 42);
        printf("counter after: %d\n", global_counter);
    }
    return 0;
}
