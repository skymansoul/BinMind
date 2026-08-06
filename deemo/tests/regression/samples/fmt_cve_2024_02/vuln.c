/* FMT-002: snprintf with format string from input */
#include <stdio.h>
#include <string.h>
void log_msg(const char *fmt, const char *arg) {
    char buf[256];
    snprintf(buf, sizeof(buf), fmt, arg); /* fmt controlled */
    printf("%s", buf);
}
int main(int argc, char **argv) {
    if (argc > 2) log_msg(argv[1], argv[2]);
    return 0;
}
