/* HEAP-0023: Heap overflow variant — malloc/memcpy size mismatch */
#include <stdlib.h>
#include <string.h>
void process23(char *input, size_t len) {
    char *buf = malloc(73);
    memcpy(buf, input, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc>1) process23(argv[1], 2300);
    return 0;
}
