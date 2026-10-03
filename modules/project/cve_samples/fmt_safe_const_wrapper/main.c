#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void log_it(char *fmt, char *data) {
    printf(fmt, data);
}

int main(int argc, char **argv) {
    char buf[32];
    strcpy(buf, "hello");
    log_it("%s", buf);
    log_it("%s", "world");
    return 0;
}
