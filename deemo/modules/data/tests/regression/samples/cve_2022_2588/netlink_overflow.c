/* CVE-2022-2588 — Linux kernel netlink heap overflow (route4_filter)
   Type: heap_overflow
   gcc -O0 netlink_overflow.c -o netlink_overflow

   Original: cls_route filter in Linux kernel had an off-by-one in the
   route4_change() hook when copying filter data, allowing heap overflow.
   This simplified version demonstrates the pattern. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned int handle; unsigned int to; unsigned int from; } route4_filter;

int route4_change(route4_filter *f, unsigned char *user_data, unsigned int data_len) {
    /* BUG: allocates data_len bytes but copies data_len + sizeof(route4_filter) */
    unsigned char *buf = (unsigned char *)malloc(data_len);
    if (!buf) return -1;

    memcpy(buf, user_data, data_len + sizeof(route4_filter));  /* heap overflow */
    printf("Filter updated: %u bytes\n", data_len);
    free(buf);
    return 0;
}

int main() {
    unsigned char data[64]; memset(data, 'C', 64);
    route4_change(NULL, data, 64);
    return 0;
}
