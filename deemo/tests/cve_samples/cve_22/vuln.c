/* Format string via syslog / CWE-134 */
#include <stdio.h>
void syslog_wrap(const char *msg) { fprintf(stderr, msg); }
int main(int argc, char **argv) {
    if (argc>1) syslog_wrap(argv[1]); return 0;
}
