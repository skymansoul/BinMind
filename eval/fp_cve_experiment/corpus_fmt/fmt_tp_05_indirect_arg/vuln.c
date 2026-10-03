/* FMT-TP-05: 格式串作参数传入 log_msg 再 printf. */
#include <stdio.h>
#include <string.h>

void log_msg(const char *fmt) {
    printf(fmt);
    printf("\n");
}

int main(int argc, char **argv) {
    char buf[64];
    strcpy(buf, argc > 1 ? argv[1] : "%d %d %s");
    log_msg(buf);
    return 0;
}
