/* CVE-2022-24407 — 堆溢出, sprintf无边界
 * 漏洞类型: 堆溢出 (sprintf写入固定缓冲区)
 * 触发条件: malloc(64), sprintf(buf, "%s", long_string)
 * 根因: sprintf不检查目标缓冲区大小
 * 有效原因: 测试无边界写入函数的检测
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void format_to_heap(char *user_input) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    /* sprintf不限制写入长度: 若user_input>64则溢出 */
    sprintf(buf, "Value: %s", user_input);
    free(buf);
}

int main() {
    char long_input[256];
    memset(long_input, 'A', 255);
    long_input[255] = 0;
    format_to_heap(long_input);
    return 0;
}
