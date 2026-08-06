/* FMT-001: Format string vulnerability — user input as format string */
#include <stdio.h>
void log_msg(const char *user) { printf(user); }
int main(int argc, char **argv) {
    if (argc > 1) log_msg(argv[1]);
    return 0;
}
