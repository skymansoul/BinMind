/* CWE-134: syslog format string via user-controlled log input */
#include <stdio.h>
#include <syslog.h>
void log_user_input(char *msg) {
    syslog(LOG_USER | LOG_NOTICE, msg); /* msg as format string */
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    openlog("vuln", LOG_PID, LOG_USER);
    log_user_input(argv[1]);
    closelog();
    return 0;
}
