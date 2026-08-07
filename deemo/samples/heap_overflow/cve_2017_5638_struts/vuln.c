/* CVE-2017-5638 — Apache Struts2 Jakarta Multipart parser (C模拟)
 * 原始漏洞: Content-Type header 中含 OGNL 注入, 异常处理时泄露/溢出.
 * 本文件为简化的 header 解析中 buffer 未校验模式.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int parse_content_type(const char *header) {
    size_t hdr_len = strlen(header);
    /* bug: fixed allocation regardless of header length */
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    /* if header > 64, overflow */
    memcpy(buf, header, hdr_len);
    printf("Content-Type: %s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    parse_content_type("multipart/form-data; boundary=----"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    return 0;
}
