/* CVE-2020-0796 — SMBv3 Compression Buffer Overflow ("SMBGhost")
   Type: buffer_overflow (stack/heap)
   gcc -O0 smb_overflow.c -o smb_overflow

   Original: SMBv3 compression transform header had an integer overflow
   in the decompressed size calculation, leading to buffer overflow.
   This simplified version shows the overflow pattern. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMPRESS_MAX 65536

/* VULNERABLE: integer overflow in size calculation */
int smb_decompress(unsigned int orig_size, unsigned int compressed_size,
                    const unsigned char *compressed_data) {
    unsigned char *decomp_buf;
    unsigned int alloc_size;

    /* BUG: orig_size + compressed_size can overflow unsigned int,
       resulting in allocation smaller than needed */
    alloc_size = orig_size + compressed_size;
    if (alloc_size > COMPRESS_MAX) return -1;

    decomp_buf = (unsigned char *)malloc(alloc_size);
    if (!decomp_buf) return -1;

    /* Overflow: memcpy can write past decomp_buf if sizes were manipulated */
    memcpy(decomp_buf, compressed_data, compressed_size);

    /* Decompression (simplified — just copies) */
    printf("Decompressed %u bytes\n", compressed_size);
    free(decomp_buf);
    return 0;
}

int main() {
    /* Crafted: orig_size=0xFFFF0000, compressed_size=0x00010000
       → alloc_size = 0 (integer overflow) */
    unsigned char data[256]; memset(data, 'A', 256);
    smb_decompress(0xFFFF0000, 0x00010000, data);
    return 0;
}
