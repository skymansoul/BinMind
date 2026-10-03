#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    /* VULN: user input directly as format string */
    printf(argv[1]);
    printf("\n");
    return 0;
}
