/* Format string vuln via heap-allocated buffer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *fmt = (char *)malloc(256);
    if (!fmt) return 1;
    if (argc > 1) strncpy(fmt, argv[1], 255);
    fmt[255] = '\0';
    printf(fmt);  /* BUG: format string vuln */
    printf("\n");
    free(fmt);
    return 0;
}
