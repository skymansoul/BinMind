/* FMT-0014: Format string variant */
#include <stdio.h>
void log14(const char *msg) { printf(msg); }
int main(int argc, char **argv) {
    if (argc > 1) log14(argv[1]);
    return 0;
}
