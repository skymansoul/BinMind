/* HEAP-0020: Heap overflow variant — malloc/memcpy size mismatch */
#include <stdlib.h>
#include <string.h>
void process20(char *input, size_t len) {
    char *buf = malloc(70);
    memcpy(buf, input, len);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc>1) process20(argv[1], 2000);
    return 0;
}
