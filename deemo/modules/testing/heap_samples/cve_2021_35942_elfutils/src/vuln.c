/* CVE-2021-35942 ¡ª elfutils: 32-bit truncation ¡ú small alloc, big copy */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void *handle_dynamic(unsigned long long big_len, const void *src) {
    unsigned int truncated = (unsigned int)big_len;  /* wraps on 64-bit sizes */
    void *buf = malloc(truncated);
    if (!buf) return NULL;
    memcpy(buf, src, (size_t)big_len);   /* BUG: copies unwrapped length */
    return buf;
}
int main(void) {
    unsigned long long len = 0x100000000ULL + 0x40;  /* truncates to 0x40 */
    unsigned char payload[0x200];
    memset(payload, 'C', sizeof(payload));
    void *p = handle_dynamic(len, payload);
    if (p) { printf("[*] ok\n"); free(p); }
    return 0;
}
