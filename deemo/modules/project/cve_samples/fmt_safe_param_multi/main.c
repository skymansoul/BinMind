#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void show(char *fmt, int v) {
    printf(fmt, v);
}

int main(int argc, char **argv) {
    int a = 1, b = 2;
    show("%d", a);
    show("%x", b);
    return 0;
}
