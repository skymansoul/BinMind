/* CVE-2020-14386: Linux AF_PACKET heap overflow
 * tp_block_size can be very large, allocation + copy leads to overflow
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup_ring_buffer(unsigned int tp_block_size, unsigned int tp_block_nr,
                       const char *user_data, size_t data_len) {
    /* BUG: multiplication overflow: tp_block_size * tp_block_nr wraps around */
    size_t ring_sz = (size_t)tp_block_size * (size_t)tp_block_nr;
    if (ring_sz > 0x80000000) ring_sz = 0x80000000;
    char *ring = (char *)malloc(ring_sz);
    if (!ring) return;
    /* 写入可能超出: data_len > ring_sz */
    memcpy(ring, user_data, data_len > ring_sz ? data_len : ring_sz);
    free(ring);
}

int main(int argc, char **argv) {
    unsigned int bs = 65536, nr = 2;
    if (argc >= 3) { bs = (unsigned int)atoi(argv[1]); nr = (unsigned int)atoi(argv[2]); }
    size_t dl = bs * nr;
    char *data = (char *)malloc(dl);
    if (data) { memset(data, 'P', dl); setup_ring_buffer(bs, nr, data, dl); free(data); }
    printf("done\n");
    return 0;
}
