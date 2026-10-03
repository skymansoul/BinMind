/* HEAP-0019: Heap overflow variant — malloc/memcpy size mismatch */
#include <stdlib.h>
#include <string.h>
void process19(char *input, size_t len) {
    char *buf = malloc(69);
    memcpy(buf, input, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc>1) process19(argv[1], 1900);
    return 0;
}
