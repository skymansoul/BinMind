/* HEAP-0017: Heap overflow variant — malloc/memcpy size mismatch */
#include <stdlib.h>
#include <string.h>
void process17(char *input, size_t len) {
    char *buf = malloc(67);
    memcpy(buf, input, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc>1) process17(argv[1], 1700);
    return 0;
}
