/* FMT-TP-04: sprintf(user_fmt, ...) 写入栈缓冲, %n 可写内存. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char out[64];
    char *fmt = argc > 1 ? argv[1] : "len=%n";
    sprintf(out, fmt);
    printf("%s\n", out);
    return 0;
}
