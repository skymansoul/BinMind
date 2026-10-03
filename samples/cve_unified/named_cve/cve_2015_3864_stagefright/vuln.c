/* CVE-2015-3864 — Android Stagefright MP4 tx3g heap overflow (simplified)
 * 原始漏洞: 解析 MP4 文件时未校验 tx3g chunk 大小, 导致整数下溢 → 堆溢出.
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int parse_tx3g_chunk(const uint8_t *data, size_t data_len) {
    if (data_len < 8) return -1;
    uint32_t chunk_size = (data[0]<<24)|(data[1]<<16)|(data[2]<<8)|data[3];
    /* bug: chunk_size may be smaller than header → size calculation underflows */
    uint32_t payload_size = chunk_size - 8; /* underflow if chunk_size < 8 */
    uint8_t *buf = (uint8_t *)malloc(payload_size);
    if (!buf) return -1;
    /* memcpy with huge size (UINT32_MAX - 8 + 1) */
    memcpy(buf, data + 8, payload_size);
    free(buf);
    return 0;
}

int main(void) {
    uint8_t crafted[] = {0,0,0,4, 0,0,0,0, 0,0}; /* chunk_size=4 → underflow */
    parse_tx3g_chunk(crafted, sizeof(crafted));
    return 0;
}
