#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char dst[256];
    if (argc < 2) return 1;
    /* VULN: user format string in sprintf */
    sprintf(dst, argv[1], 0x41414141);
    printf("result: %s\n", dst);
    return 0;
}
