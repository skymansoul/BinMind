/* FMT-0012: Format string variant */
#include <stdio.h>
void log12(const char *msg) { printf(msg); }
int main(int argc, char **argv) {
    if (argc > 1) log12(argv[1]);
    return 0;
}
