/* HEAP-0024: Heap overflow variant — malloc/memcpy size mismatch */
#include <stdlib.h>
#include <string.h>
void process24(char *input, size_t len) {
    char *buf = malloc(74);
    memcpy(buf, input, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc>1) process24(argv[1], 2400);
    return 0;
}
