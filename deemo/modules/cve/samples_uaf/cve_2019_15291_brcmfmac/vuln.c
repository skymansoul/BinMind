/* CVE-2019-15291 Broadcom brcmfmac: 释放缓冲区后 memcpy 读入. */
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
