/* FMT-TP-02: snprintf 拼接入栈缓冲, 再 printf 该缓冲. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[256];
    snprintf(fmt, sizeof(fmt), "prefix:%s", argc > 1 ? argv[1] : "%s");
    printf(fmt, "x");
    return 0;
}
