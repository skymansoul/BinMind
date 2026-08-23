/* CVE-2016-10190 — FFmpeg RTMP heap overflow (simplified reproduction)
 * 真实漏洞: FFmpeg libavformat/rtmppkt.c 中 rtmp_packet_read_one_chunk
 *   未充分校验 chunk size 导致堆溢出.
 * 本文件为简化的漏洞模式复现, 用于测试静态检测能力.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

struct rtmp_packet {
    uint32_t header_size;
    uint32_t body_size;
    uint8_t *data;
};

/* 漏洞模式: header_size 来自网络输入, body_size 也来自网络输入,
   若 header_size > body_size → 读取越界; 若 body_size > 分配大小 → 溢出. */
int process_rtmp_packet(uint32_t hdr_sz, uint32_t body_sz, const uint8_t *input) {
    uint32_t total = hdr_sz + body_sz;
    /* bug: total may overflow uint32 or allocate smaller than needed */
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return -1;
    /* if total overflowed, buf is smaller than expected → overflow */
    memcpy(buf, input, hdr_sz + body_sz);
    free(buf);
    return 0;
}

int main(void) {
    /* Craft overflow: hdr_sz=0xFFFFFF00 + body_sz=0x200 → total=0x100 (overflow) */
    uint8_t input[512];
    memset(input, 'X', sizeof(input));
    process_rtmp_packet(0xFFFFFF00, 0x200, input);
    return 0;
}
