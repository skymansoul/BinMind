/*
 * CVE-2014-0160 (Heartbleed) 模式复刻 — 堆信息泄漏/越界读取
 * 真实漏洞: OpenSSL TLS heartbeat 扩展未校验 payload 长度
 * 触发条件: heartbeat 请求声明 payload_len 大于实际发送字节
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct heartbeat {
    unsigned short type;
    unsigned short len;
    char payload[16];
};

int main(int argc, char **argv) {
    struct heartbeat *hb = (struct heartbeat *)malloc(16);
    if (!hb) return 1;
    hb->type = 1;
    hb->len = 20;  /* 声明长度 20 > 实际 payload 16 */
    memcpy(hb->payload, "ABCDEFGH", 8);
    /* 越界读取: 将 payload_len 字节复制到响应缓冲区 */
    memcpy(malloc(64), hb->payload, hb->len);
    free(hb);
    return 0;
}
