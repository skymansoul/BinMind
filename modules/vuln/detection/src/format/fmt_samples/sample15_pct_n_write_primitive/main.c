#include <stdio.h>

int main(int argc, char **argv) {
    int target = 0;
    if (argc < 2) return 1;
    /* VULN: %n writes to &target via format string */
    printf(argv[1], &target);
    printf("target after fmt: %d (0x%x)\n", target, target);
    return 0;
}
