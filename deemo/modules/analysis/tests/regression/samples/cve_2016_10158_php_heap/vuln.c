/* CVE-2016-10158: PHP exif_process_IFD_TAG heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void exif_process_tag(uint16_t tag_count, const uint8_t *tag_data, size_t data_len) {
    /* BUG: tag_count * 12 may overflow, leading to small alloc */
    size_t alloc_sz = (size_t)tag_count * 12 + 32;
    if (alloc_sz > 0x100000) alloc_sz = 0x100000;
    uint8_t *buf = (uint8_t *)malloc(alloc_sz);
    if (!buf) return;
    /* 实际复制 data_len 字节, 可能远超 alloc_sz */
    size_t copy_sz = data_len < alloc_sz + 256 ? data_len : alloc_sz;  /* BUG: +256 */
    memcpy(buf, tag_data, copy_sz);
    free(buf);
}

int main(int argc, char **argv) {
    uint16_t count = 500;
    if (argc >= 2) count = (uint16_t)atoi(argv[1]);
    size_t dl = (size_t)count * 12 + 4096;
    uint8_t *data = (uint8_t *)malloc(dl);
    if (data) { memset(data, 'E', dl); exif_process_tag(count, data, dl); free(data); }
    printf("done\n");
    return 0;
}
