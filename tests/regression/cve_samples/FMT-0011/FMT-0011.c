/* FMT-0011: Format string variant */
#include <stdio.h>
void log11(const char *msg) { printf(msg); }
int main(int argc, char **argv) {
    if (argc > 1) log11(argv[1]);
    return 0;
}
