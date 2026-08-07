/* FMT TP sample */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int flag = argc > 1 ? atoi(argv[1]) : 0;
    if (flag && argc > 2) { printf(argv[2]); }
    return 0;
}
