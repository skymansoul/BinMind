/* CVE-2020-14386 AF_PACKET tpacket: 释放后 memcpy 越界读. */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    char dst[64];
    if (!p) return 1;
    free(p);
    memcpy(dst, p, 16);
    return 0;
}
