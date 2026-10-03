#include <stdio.h>

int main(int argc, char **argv) {
    int secret = 0xdeadbeef;
    if (argc < 2) return 1;
    /* VULN: format string leaks stack data */
    printf(argv[1], secret);
    printf("\n");
    return 0;
}
