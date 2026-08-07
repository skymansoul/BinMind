/* HEAP-OVERFLOW-LOOP-02: loop-based heap overflow, N items written to M-size buf (N>M). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int count = argc > 1 ? atoi(argv[1]) : 100;
    int *buf = malloc(16 * sizeof(int));  /* 16 ints = 64 bytes */
    for (int i = 0; i < count; i++) {
        buf[i] = i;  /* overflow when count > 16 */
    }
    printf("last=%d\n", buf[count-1]);
    free(buf);
    return 0;
}
