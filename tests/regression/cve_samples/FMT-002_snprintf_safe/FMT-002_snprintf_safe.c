/* FMT-002: Safe pattern — snprintf with bounded size */
#include <stdio.h>
void format_msg(const char *user) {
    char buf[256];
    snprintf(buf, sizeof(buf), "User: %s", user);
    printf("%s", buf);
}
int main(int argc, char **argv) {
    if (argc > 1) format_msg(argv[1]);
    return 0;
}
