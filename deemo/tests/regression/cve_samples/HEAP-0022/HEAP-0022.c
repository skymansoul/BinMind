/* HEAP-0022: Heap overflow variant — malloc/memcpy size mismatch */
#include <stdlib.h>
#include <string.h>
void process22(char *input, size_t len) {
    char *buf = malloc(72);
    memcpy(buf, input, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc>1) process22(argv[1], 2200);
    return 0;
}
