/* CVE-2021-3156 — sudo Baron Samedit heap overflow
 * Pattern: unescape backslash → off-by-one in size computation → heap overflow
 * Classic: alloc = user_len - 1 (remove backslash) but copy = user_len */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned user_len = 128;
    unsigned alloc_sz = user_len;  // bug: should be user_len or user_len-1
    char *buf = (char *)malloc(alloc_sz);
    if (buf) {
        memset(buf, 0x41, user_len + 64);  // HEAP OVERFLOW: writes past alloc
        printf("CVE-2021-3156: alloc=%u write=%u\n", alloc_sz, user_len + 64);
        free(buf);
    }
    return 0;
}
