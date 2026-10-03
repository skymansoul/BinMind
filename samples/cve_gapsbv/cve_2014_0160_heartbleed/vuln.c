/*
 * CVE-2014-0160 — Heartbleed (OpenSSL 1.0.1 ~ 1.0.1f)
 *
 * 漏洞本质: 堆越界读 — TLS heartbeat 请求中的 payload_length 字段未经验证,
 * 攻击者声称 payload 长度为 65535 字节, 但实际数据只有 0 或 1 字节,
 * 导致 memcpy 从堆缓冲区读取超出分配边界的敏感数据 (私钥、cookie 等).
 *
 * 受影响的分配: ssl3_read_bytes 中的 TLS 记录缓冲区
 * 触发条件: payload_length > actual_payload 且未做边界检查
 *
 * 文献: Durumeric et al., "The Matter of Heartbleed", IMC 2014.
 * CWE-126: 缓冲区越界读
 * CVSS: 7.5 (High), CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 精简版 Heartbleed: 模拟 dtls1_process_heartbeat */
typedef struct {
    uint16_t payload_length;
    unsigned char payload[0];
} heartbeat_t;

int process_heartbeat(unsigned char *pkt, unsigned int pkt_len) {
    if (pkt_len < 3) return -1;

    heartbeat_t *hb = (heartbeat_t *)pkt;

    /* [VULN] 未验证 hb->payload_length ≤ (pkt_len - 3)
     * 攻击者设 payload_length=65535, pkt_len=4 (仅1字节payload)
     * → 分配 65535 字节, 但响应填充 65535 字节来自堆中紧邻数据
     */
    unsigned int payload_sz = hb->payload_length; /* 攻击者可控, 可达 65535 */
    unsigned int actual_sz = pkt_len - 3;         /* 实际仅 1 字节 */

    /* 分配响应缓冲区 — 信任攻击者声明的长度 */
    unsigned char *response = (unsigned char *)malloc(payload_sz + 16);
    if (!response) return -1;

    /* [VULN] memcpy 拷贝了攻击者声称的量, 但源数据只有 actual_sz 字节
     * 超出部分来自堆中其他对象 — 信息泄露
     */
    memcpy(response + 16, hb->payload, payload_sz); /* ← 越界读 */

    /* 正常流程 ... */
    free(response);
    return 0;
}

int main(void) {
    /* 模拟攻击: 1字节 payload, 声称65535 */
    unsigned char pkt[4] = {0xFF, 0xFF, 0x00, 0x41}; /* length=65535, payload='A' */
    return process_heartbeat(pkt, 4);
}
