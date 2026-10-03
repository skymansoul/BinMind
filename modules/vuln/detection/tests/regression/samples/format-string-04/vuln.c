/* format-string-04: 用户输入直接作为printf格式字符串
 * 类型: format string vulnerability
 * Ground Truth: printf(user_input) 中格式字符串可控
 */
#include <stdio.h>
#include <unistd.h>
void log_msg() {
    char buf[256]; read(0, buf, 255);
    printf(buf);  /* BUG: 格式字符串可控 */
}
int main() { log_msg(); return 0; }
