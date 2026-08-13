#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    syslog(LOG_ERR, argv[1]);
    return 0;
}
