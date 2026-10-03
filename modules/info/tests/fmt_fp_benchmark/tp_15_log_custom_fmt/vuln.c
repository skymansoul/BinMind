/* FMT TP sample */
#include <stdio.h>
static void log_msg(const char *m) { printf(m); }
int main(int argc, char **argv) {
    if (argc > 1) { log_msg(argv[1]); }
    return 0;
}
