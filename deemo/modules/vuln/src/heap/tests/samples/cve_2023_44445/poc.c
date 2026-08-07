/* CVE-2023-44445 — KSMBD session setup heap overflow
 * Pattern: ntlm_negotiate → malloc(type2_size) where type2_size is user-controlled
 * Minimized: malloc(user_size) → memcpy with user_size + offset */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned user_sz = 0x100;
    char *buf = (char *)malloc(user_sz);
    if (buf) {
        unsigned copy_sz = user_sz + 0x80;  // extra NTLM fields exceed allocation
        memset(buf, 0x41, copy_sz);  // HEAP OVERFLOW
        printf("CVE-2023-44445: alloc=%u write=%u\n", user_sz, copy_sz);
        free(buf);
    }
    return 0;
}
