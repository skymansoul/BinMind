/* FMT-001: 安全的.rodata常量格式串——不应报告
 * 场景: printf(gettext("hello %s", name)) — fmt来自.rodata翻译字符串
 * 检测器能力: lea rdi, [rip+offset] → CONST_RODATA → SAFE
 * 预期: 格式串检测器判定SAFE
 */

#include <stdio.h>

#define WELCOME_MSG "Welcome, %s! You have %d messages.\n"

void show_welcome(const char *username, int msg_count) {
    /* fmt在.rodata中——完全安全 */
    printf(WELCOME_MSG, username, msg_count);
}

void log_status(int code) {
    const char *msg;
    switch (code) {
        case 0: msg = "OK: %d\n"; break;
        case 1: msg = "WARN: %d\n"; break;
        default: msg = "ERR: %d\n"; break;
    }
    /* msg指向.rodata中的字符串——安全 */
    printf(msg, code);
}

int main(void) {
    show_welcome("Alice", 5);
    log_status(0);
    return 0;
}
