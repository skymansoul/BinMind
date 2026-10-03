/* FMT TP sample */
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc > 1) { syslog(0, argv[1]); }
    return 0;
}
