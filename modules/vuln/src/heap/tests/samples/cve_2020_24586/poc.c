/* CVE-2020-24586 — Linux kernel WiFi frame re-assembly overflow
 * Pattern: fragment chain → malloc(total_size) but total_size wraps/underflows */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned frag1 = 0xFFFF;
    unsigned frag2 = 0xFFF0;
    unsigned total = frag1 + frag2;  // wraps: 0x1FFEF > 16-bit? Actually 0x1FFEF
    unsigned wrapped = (unsigned short)total;  // truncation: 0xFFEF
    char *buf = (char *)malloc(wrapped);  // allocates 0xFFEF but actual is 0x1FFEF
    if (buf) {
        memset(buf, 0x41, total);  // HEAP OVERFLOW
        printf("CVE-2020-24586: alloc=%u write=%u\n", wrapped, total);
        free(buf);
    }
    return 0;
}
