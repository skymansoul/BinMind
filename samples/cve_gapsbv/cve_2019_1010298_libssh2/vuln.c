/*
 * CVE-2019-1010298 — libssh2: SSH_MSG_CHANNEL_OPEN 堆溢出 (CWE-122)
 *
 * libssh2 1.9.0 之前: kex_method_diffie_hellman_group_exchange_sha256_key_exchange
 * 中未验证服务器发送的 SSH_MSG_KEX_DH_GEX_GROUP 数据长度,
 * 攻击者控制的 p 值长度 < 预期时, 在 memcpy 时读到堆外的数据.
 *
 * 更直接的问题: 处理通道打开时, 攻击者控制的 channel_type 字符串
 * 被分配了错误的大小, 导致堆越界.
 *
 * CVSS: 7.5 (High), CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 模拟 SSH 通道打开处理 */
int ssh_channel_open(uint32_t sender_channel,
                     uint32_t window_sz,
                     uint32_t packet_sz,
                     const unsigned char *payload,
                     uint32_t payload_len) {

    /* [VULN] window_sz 和 packet_sz 来自攻击者,
     * 分配时使用 window_sz, 但写入时使用 packet_sz
     * (packet_sz > window_sz → 溢出)
     */
    if (window_sz == 0 || window_sz > 0x100000) {
        return -1;
    }

    char *channel_buf = (char *)malloc(window_sz);
    if (!channel_buf) return -2;

    /* [VULN] packet_sz 可能远大于 window_sz,
     * 但代码未做 packet_sz ≤ window_sz 的检查
     */
    size_t copy_sz = packet_sz;
    if (copy_sz > payload_len)
        copy_sz = payload_len;
    /* 注意: 仍未检查 copy_sz ≤ window_sz! */

    memcpy(channel_buf, payload, copy_sz); /* ← 越界写 */

    /* ... 处理通道数据 ... */
    free(channel_buf);
    return 0;
}

int main(void) {
    unsigned char pkt[16384];
    memset(pkt, 'S', sizeof(pkt));

    /* window_sz=4096, packet_sz=16384 — 攻击者控制 */
    return ssh_channel_open(1, 4096, 16384, pkt, sizeof(pkt));
}
