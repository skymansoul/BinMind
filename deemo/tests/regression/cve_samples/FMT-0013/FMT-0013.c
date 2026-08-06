/* FMT-0013: Format string variant */
#include <stdio.h>
void log13(const char *msg) { printf(msg); }
int main(int argc, char **argv) {
    if (argc > 1) log13(argv[1]);
    return 0;
}
