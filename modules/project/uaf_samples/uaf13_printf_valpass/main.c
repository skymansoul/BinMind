#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    printf("addr=%p\n", (void *)p);
    return 0;
}
