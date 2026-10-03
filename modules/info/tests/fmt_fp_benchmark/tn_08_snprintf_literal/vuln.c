/* FMT TN (safe) sample */
#include <stdio.h>
int main(int argc, char **argv) {
    char out[128];
    snprintf(out, sizeof(out), "%s", argc > 1 ? argv[1] : "x");
    return 0;
}
