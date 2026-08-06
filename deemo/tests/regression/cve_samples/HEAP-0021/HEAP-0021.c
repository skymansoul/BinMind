/* HEAP-0021: Heap overflow variant — malloc/memcpy size mismatch */
#include <stdlib.h>
#include <string.h>
void process21(char *input, size_t len) {
    char *buf = malloc(71);
    memcpy(buf, input, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc>1) process21(argv[1], 2100);
    return 0;
}
