#include <stdio.h>
#include <stdarg.h>

void log_message(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    /* VULN: fmt passed through without validation */
    vprintf(fmt, args);
    va_end(args);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_message(argv[1]);
    printf("\n");
    return 0;
}
