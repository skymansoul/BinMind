/* CVE-2015-3456 (VENOM): QEMU floppy controller heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fdctrl_write_data(uint32_t fifo_size, const uint8_t *fifo_data) {
    /* BUG: alloc_sz = fifo_size, but fifo_size can be any value */
    uint8_t *buf = (uint8_t *)malloc(fifo_size + 1);
    if (!buf) return;
    /* 写入可能超出: 若 fifo_size 被篡改为超大值 */
    memcpy(buf, fifo_data, fifo_size);
    buf[fifo_size] = '\0';
    free(buf);
}

int main(int argc, char **argv) {
    uint32_t sz = (argc >= 2) ? (uint32_t)atoi(argv[1]) : 4096;
    uint8_t *data = (uint8_t *)malloc(sz);
    if (data) { memset(data, 0x41, sz); fdctrl_write_data(sz, data); free(data); }
    printf("done\n");
    return 0;
}
