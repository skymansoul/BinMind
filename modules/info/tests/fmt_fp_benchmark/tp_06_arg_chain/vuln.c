/* FMT TP sample */
#include <stdio.h>
static void emit(const char *fmt) { printf(fmt); }
int main(int argc, char **argv) {
    if (argc > 1) { emit(argv[1]); }
    return 0;
}
