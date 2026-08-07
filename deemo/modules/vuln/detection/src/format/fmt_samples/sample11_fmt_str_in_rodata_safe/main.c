#include <stdio.h>

static const char *STATUS_FMT = "Status: %s (code=%d)\n";

int main(void) {
    const char *name = "test_service";
    int code = 200;
    /* SAFE: format string from read-only data */
    printf(STATUS_FMT, name, code);
    return 0;
}
