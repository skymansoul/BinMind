/* CVE-2020-10713 — GRUB2 BootHole heap overflow
 * Pattern: grub_strlen → malloc → grub_memcpy with user data exceeding buffer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned token_sz = 0x1000;
    char *buf = (char *)malloc(64);
    if (buf) {
        memset(buf, 0x41, token_sz);  // token_sz (4096) >> alloc (64) → HEAP OVERFLOW
        printf("CVE-2020-10713: alloc=64 write=%u\n", token_sz);
        free(buf);
    }
    return 0;
}
