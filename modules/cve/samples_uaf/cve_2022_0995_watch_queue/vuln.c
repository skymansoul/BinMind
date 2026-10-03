/* CVE-2022-0995 watch_queue filter: 释放后经 printf 使用. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    printf("%s\n", p);
    return 0;
}
