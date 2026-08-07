/* CVE-2019-16935 — 堆溢出, strstr长度不匹配
 * 漏洞类型: 堆溢出 (动态长度溢出)
 * 触发条件: malloc(strlen(input)), 处理后写入strlen(input)+header_size
 * 根因: 分配strlen(input), 写入strlen(input)+16
 * 有效原因: 测试动态长度来源(strlen返回值)的符号传播
 */
#include <stdlib.h>
#include <string.h>

void parse_header(char *input) {
    size_t input_len = strlen(input);
    char *buf = (char *)malloc(input_len);  /* 分配input_len */
    if (!buf) return;
    /* 写入header(16字节) + input_len: 溢出16字节 */
    memcpy(buf, "HEADER: 0x0000: ", 16);
    memcpy(buf + 16, input, input_len);    /* 偏移16+input_len > input_len */
    free(buf);
}

int main() {
    char data[256] = "test";
    parse_header(data);
    return 0;
}
