/* FMT-003: syslog with user-controlled format */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
int main(int argc, char **argv) {
    openlog("fmt_test", LOG_PID, LOG_USER);
    if (argc > 1) syslog(LOG_ERR, argv[1]); /* FORMAT STRING in syslog */
    closelog();
    return 0;
}
