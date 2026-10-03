/* CWE-134: snprintf with user format string */
#include <stdio.h>
void format_output(char *fmt, char *val) {
    char buf[256];
    snprintf(buf, sizeof(buf), fmt, val); /* fmt is user-controlled */
    printf("%s\n", buf);
}
int main(int argc, char **argv) {
    if (argc < 3) return 1;
    format_output(argv[1], argv[2]);
    return 0;
}
