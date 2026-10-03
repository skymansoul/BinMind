#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    snprintf(buf, 128, "%s", argc > 1 ? argv[1] : "hi");
    printf("%s\n", buf);
    free(buf);
    return 0;
}
