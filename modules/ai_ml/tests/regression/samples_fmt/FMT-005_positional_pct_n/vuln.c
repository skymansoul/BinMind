/* FMT-005: 位置参数+%n——最复杂的格式串攻击面
 * 场景: printf("%1$s%2$n", str, &counter) — 位置参数绕过参数顺序
 * 检测器能力: 识别位置参数格式(%1$...) + %n → CRITICAL
 * 预期: 位置参数检测+%n→CRITICAL风险
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int log_counter = 0;
int error_count = 0;

/* BUG: 位置参数+%n——攻击者可控制写入目标 */
void positional_fmt_vuln(const char *user_fmt, const char *data) {
    /* %1$s指向data, %2$n写入&log_counter.
     * 攻击者可通过调整输出宽度(%1$100s%2$n)写入任意值 */
    printf(user_fmt, data, &log_counter);
}

/* BUG: snprintf宽字符计数——%n在截断后仍写入 */
void truncation_vuln(char *output, size_t out_size, const char *input) {
    int written = 0;
    /* 若input很长，snprintf截断，但%n记录的是截断前的"理想"长度 */
    snprintf(output, out_size, "%s%n", input, &written);
    printf("would have written: %d bytes\n", written);
    /* BUG: written可能>out_size，后续使用可能越界 */
    if (written > (int)out_size) {
        printf("overflow condition: %d > %zu\n", written, out_size);
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        positional_fmt_vuln(argv[1], "sensitive_data");
        printf("log_counter after: %d\n", log_counter);
    }

    char buf[64];
    truncation_vuln(buf, sizeof(buf),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return 0;
}
