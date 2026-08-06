/* FMT-004: syslog with user format string */
#include <syslog.h>
void log_event(const char *user) { syslog(LOG_INFO, user); }
int main(int argc, char **argv) {
    if (argc > 1) log_event(argv[1]);
    return 0;
}
