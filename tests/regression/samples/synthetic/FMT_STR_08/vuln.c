/* CWE-134: fprintf to open file with user format */
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 3) return 1;
    FILE *f = fopen(argv[1], "w");
    if (!f) return 1;
    fprintf(f, argv[2]); fclose(f);
    return 0;
}
