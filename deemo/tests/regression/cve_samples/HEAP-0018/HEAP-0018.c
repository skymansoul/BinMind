/* HEAP-0018: Heap overflow variant — malloc/memcpy size mismatch */
#include <stdlib.h>
#include <string.h>
void process18(char *input, size_t len) {
    char *buf = malloc(68);
    memcpy(buf, input, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc>1) process18(argv[1], 1800);
    return 0;
}
