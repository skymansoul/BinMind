/* HEAP-0016: Heap overflow variant — malloc/memcpy size mismatch */
#include <stdlib.h>
#include <string.h>
void process16(char *input, size_t len) {
    char *buf = malloc(66);
    memcpy(buf, input, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc>1) process16(argv[1], 1600);
    return 0;
}
