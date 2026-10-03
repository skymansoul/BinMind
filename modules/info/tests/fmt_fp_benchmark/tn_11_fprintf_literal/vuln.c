/* FMT TN (safe) sample */
#include <stdio.h>
int main(int argc, char **argv) {
    fprintf(stderr, "err=%s\n", argc > 1 ? argv[1] : "?");
    return 0;
}
