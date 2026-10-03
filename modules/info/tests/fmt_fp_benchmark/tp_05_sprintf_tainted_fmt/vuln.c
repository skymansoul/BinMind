/* FMT TP sample */
#include <stdio.h>
int main(int argc, char **argv) {
    char out[256];
    if (argc > 1) { sprintf(out, argv[1], 1); }
    return 0;
}
