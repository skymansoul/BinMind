/* FMT TN (safe) sample */
#include <stdio.h>
int main(int argc, char **argv) {
    printf("arg=%s\n", argc > 1 ? argv[1] : "none");
    return 0;
}
