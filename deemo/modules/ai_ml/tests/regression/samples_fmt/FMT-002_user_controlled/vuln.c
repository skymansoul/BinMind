/* FMT-002: 用户可控格式串——栈变量直接作为fmt
 * 场景: char buf[256]; read(0, buf, 256); printf(buf);
 * 检测器能力: mov rdi, [rbp-N] → STACK → DANGEROUS
 * 预期: 格式串检测器判定DANGEROUS
 */

#include <stdio.h>
#include <string.h>

void echo_user_input(const char *input) {
    /* BUG: 直接将用户输入作为格式串
     * 用户输入"%s%s%s" → 栈泄露
     * 用户输入"%n" → 任意地址写 */
    printf(input);
}

void parse_and_print(char *line) {
    char temp[512];
    strncpy(temp, line, sizeof(temp) - 1);
    temp[511] = '\0';

    /* BUG: temp是栈变量，内容来自用户 */
    printf(temp);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        echo_user_input(argv[1]);
    }

    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        parse_and_print(buf);
    }
    return 0;
}
