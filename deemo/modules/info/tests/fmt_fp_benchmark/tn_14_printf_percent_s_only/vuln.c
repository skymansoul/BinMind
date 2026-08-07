/* FMT TN (safe) sample */
#include <stdio.h>
int main(int argc, char **argv) {
    printf("v=%s n=%d\n", argc > 1 ? argv[1] : "", 0);
    return 0;
}
