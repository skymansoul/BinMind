#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *fmt = (char *)malloc(128);
    if (!fmt) return 1;
    snprintf(fmt, 128, "%s", argv[1]);
    printf(fmt);                  /* 用户可控 + %n 风险 */
    free(fmt);
    return 0;
}
