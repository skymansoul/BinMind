#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-07: 堆上的格式串 — 格式串存储在堆而非栈 */
int main(int argc, char **argv) {
    char *fmt = (char *)malloc(256);
    if (!fmt) return 1;
    if (argc > 1) strcpy(fmt, argv[1]);
    else strcpy(fmt, "heap fmt: %s");
    printf(fmt, "test");  /* VULNERABLE if argc>1 */
    free(fmt);
    return 0;
}
