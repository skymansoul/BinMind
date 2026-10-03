#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-13: 位域提取溢出 — 从网络/文件解析的长度字段可能为大值
 * CWE-190: Integer Overflow when parsing untrusted length fields */
unsigned int parse_len(const unsigned char *data) {
    /* 模拟解析24位大端长度字段 */
    return (data[0] << 16) | (data[1] << 8) | data[2];
}
int main(void) {
    unsigned char pkt[] = {0xFF, 0xFF, 0xFF};  /* 16MB - 1 */
    unsigned int len = parse_len(pkt);
    /* VULNERABLE: len+1溢出回绕到0 */
    char *buf = (char *)malloc(len + 1);
    if (!buf) return 1;
    memset(buf, 0, len + 1);  /* len+1溢出为0, memset(0)无操作 */
    free(buf);
    return 0;
}
