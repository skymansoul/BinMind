/* FMT TN (safe) sample */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int flag = argc > 1 ? atoi(argv[1]) : 0;
    if (flag) { printf("yes\n"); } else { printf("no\n"); }
    return 0;
}
