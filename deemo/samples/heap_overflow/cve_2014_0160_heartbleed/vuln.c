/* CVE-2014-0160 — Heartbleed (simplified heap over-read pattern)
 * 原始漏洞: OpenSSL TLS heartbeat 中未校验 payload_length,
 *   导致越界读取堆内存. 虽是 over-read, 但检测模式与 heap buffer overflow 高度重叠.
 * 本文件简化复现核心模式: user-controlled length fed to memcpy on heap buffer.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

struct heartbeat_msg {
    uint16_t payload_length;
    uint8_t payload[0];
};

int handle_heartbeat(const uint8_t *pkt, size_t pkt_len) {
    if (pkt_len < 2) return -1;
    uint16_t claimed_len = (pkt[0] << 8) | pkt[1];
    /* bug: claimed_len not validated against actual payload size */
    uint8_t *response = (uint8_t *)malloc(claimed_len + 2);
    if (!response) return -1;
    response[0] = pkt[0]; response[1] = pkt[1];
    /* if claimed_len > actual payload, this copies uninitialized heap data */
    memcpy(response + 2, pkt + 2, claimed_len);
    /* write back without proper bounds check */
    free(response);
    return 0;
}

int main(void) {
    /* Craft packet: claim 65535 bytes but provide only 16 */
    uint8_t pkt[16];
    pkt[0] = 0xFF; pkt[1] = 0xFF; /* length = 65535 */
    memset(pkt + 2, 'A', 14);
    handle_heartbeat(pkt, 16);
    return 0;
}
