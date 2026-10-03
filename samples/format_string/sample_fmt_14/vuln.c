/*
 * sample_fmt_14 — fprintf(stderr, user_input) (CWE-134 变体)
 * 模式: fgets → fprintf(stderr, user_input)  — fprintf 作为 sink
 * 期望: CONFIRMED (置信度 ≥ 0.60)
 *
 * 关键点: fprintf 与 printf 同为格式字符串 sink,
 *         检测器必须覆盖 fprintf / dprintf / vfprintf 等变体
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 256

// 危险: 错误消息中使用用户输入作为格式字符串
// fprintf(stderr, user) 与 printf(user) 同样危险
void log_error(const char *user_msg) {
    // CWE-134: fprintf 的第一个参数是用户输入
    // 攻击者可注入 %s 读取栈内容, %n 写入任意地址
    fprintf(stderr, user_msg);
    fprintf(stderr, "\n");
}

int main(void) {
    char buffer[MAX_INPUT];

    printf("Enter error message: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        return 1;
    }

    // 去除换行
    buffer[strcspn(buffer, "\n")] = '\0';

    // 危险调用 — user_msg 直接作为格式字符串传给 fprintf
    log_error(buffer);

    // 对比: 安全模式
    fprintf(stderr, "User said: %s\n", buffer);  // 安全 (固定格式字符串)

    return 0;
}
