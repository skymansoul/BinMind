/* heap_off_by_one: off-by-one heap overflow.
   malloc(N), write N+1 bytes. The single-byte overflow can corrupt
   adjacent chunk metadata. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int sz = argc > 1 ? atoi(argv[1]) : 16;
    char *buf = malloc(sz);
    if (!buf) return 1;
    memset(buf, 'X', sz + 1);  /* off-by-one overflow */
    free(buf);
    return 0;
}
