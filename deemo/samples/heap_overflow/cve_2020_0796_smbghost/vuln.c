/* CVE-2020-0796 — SMBGhost / EternalDarkness (simplified pattern)
 * 原始漏洞: Windows SMBv3 压缩解压中整数溢出导致堆分配不足.
 * 关键模式: OriginalSize 和 Offset 未充分校验, decompress 写越界.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

int decompress_smb_data(uint32_t orig_size, uint32_t offset,
                        const uint8_t *compressed, uint32_t comp_size) {
    /* bug: offset may exceed orig_size, or orig_size + offset wraps */
    uint32_t alloc_size = orig_size + offset;
    if (alloc_size < orig_size) {
        printf("integer overflow in alloc_size\n");
    }
    uint8_t *buf = (uint8_t *)malloc(alloc_size);
    if (!buf) return -1;
    /* write compressed data into buf starting at offset */
    /* if offset is near UINT32_MAX and orig_size is small → overflow */
    memcpy(buf + offset, compressed, comp_size);
    free(buf);
    return 0;
}

int main(void) {
    uint8_t data[256];
    memset(data, 'C', sizeof(data));
    /* offset=0xFFFF0000 + orig_size=0x10000 → wraps to 0x10000 alloc, but offset huge */
    decompress_smb_data(0x10000, 0xFFFF0000, data, 256);
    return 0;
}
