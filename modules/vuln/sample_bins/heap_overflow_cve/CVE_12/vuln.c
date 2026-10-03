/* CVE-2014-0160 (Heartbleed简化版) — 堆溢出读取
 * 漏洞类型: 堆越界读 (Heartbleed模式)
 * 触发条件: malloc(payload_len), 读取payload_len+额外字节
 * 根因: 分配用户请求的payload长度, 但读取payload+16字节
 * 有效原因: 经典OpenSSL Heartbleed, 测试越界读检测
 */
#include <stdlib.h>
#include <string.h>

void process_heartbeat(char *payload, unsigned short payload_len) {
    char *response = (char *)malloc(payload_len + 1);
    if (!response) return;
    /* 正确: 只复制payload_len字节 */
    memcpy(response, payload, payload_len);
    /* 模拟漏洞: 额外读取16字节(泄露内存) */
    memset(response + payload_len, 0, 16);
    free(response);
}

int main() {
    char data[256] = "heartbeat";
    process_heartbeat(data, 9);
    return 0;
}
