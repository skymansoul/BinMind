/* sample05: 格式化字符串到堆缓冲区 — 双重漏洞
 *
 * 漏洞类型: Format string + potential heap overflow
 * 触发条件: 用户输入直接作为格式字符串, 且sprintf到固定大小堆缓冲区
 * 测试价值: 多漏洞类型共存场景, 验证堆检测不受fmt检测干扰
 */
#include <stdio.h>
#include <stdlib.h>

void log_message(const char *user_input) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    // [VULN-1] 格式化字符串漏洞: user_input直接作为格式字符串
    // [VULN-2] 若user_input超长, sprintf可能溢出128字节堆缓冲区
    sprintf(buf, user_input);
    printf("LOG: %s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <format_string>\n", argv[0]); return 1; }
    log_message(argv[1]);
    return 0;
}
