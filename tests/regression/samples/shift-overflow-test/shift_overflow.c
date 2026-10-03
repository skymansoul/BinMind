/* Left shift overflow test
 * gcc -g -O0 -o vuln shift_overflow.c */
#include <stdio.h>
#include <stdlib.h>
void alloc_shifted(int count) {
    int size = 1 << count; /* overflow if count >= 31 for signed int */
    char *buf = malloc(size);
    free(buf);
}
int main(int argc, char **argv) {
    if(argc<2) return 1;
    alloc_shifted(atoi(argv[1]));
    return 0;
}