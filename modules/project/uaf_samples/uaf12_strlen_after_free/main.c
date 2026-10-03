#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "hello");
    free(p);
    size_t n = strlen(p);
    printf("%zu\n", n);
    return 0;
}
