/* CVE-2021-32399 块层 blk-mq: 释放请求后 memset 清零. */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    memset(p, 0, 16);
    return 0;
}
