/* CVE-2023-0461 io_uring: 释放固定文件表后 memcpy 访问. */
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
