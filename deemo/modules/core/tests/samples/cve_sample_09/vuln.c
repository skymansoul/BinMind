/* CVE-2014-0160 — Heartbleed (模拟堆过读/过写)
 * 真实: OpenSSL 1.0.1-1.0.1f, 心跳包的 payload length 字段未验证
 * 漏洞: 用户提供的 payload_len > 实际 payload 大小 → 越界读取+回显
 * 此处模拟: 如果写入而非读取 → 堆溢出 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void heartbeat_response(char *payload, unsigned int declared_len,
                        unsigned int actual_len) {
    char *buf = (char *)malloc(declared_len);
    if (!buf) return;
    /* 漏洞: declared_len 可能远大于 actual_len */
    memcpy(buf, payload, declared_len); /* 溢出: declared_len > actual_len */
    printf("echo: %s\n", buf);
    free(buf);
}

int main(void) {
    char payload[] = "hello";
    /* declared_len=65535, actual_len=5 → 溢读+溢写 */
    heartbeat_response(payload, 65535, 5);
    return 0;
}
