/* CVE-2015-8612 — systemd journald format string
   Type: format_string   gcc -O0 systemd_fmt.c -o systemd_fmt
   systemd journald passed attacker-controlled syslog data
   as format string to printf. */
#include <stdio.h>
#include <string.h>
void log_journal_entry(const char *uid, const char *message) {
    char buf[1024];
    snprintf(buf, sizeof(buf), message, uid);  /* BUG: message is format string */
    printf("[JOURNAL] %s\n", buf);
}
int main(int argc, char **argv) {
    log_journal_entry("1000", argc>1 ? argv[1] : "%x%x%x%s%n");
    return 0;
}
