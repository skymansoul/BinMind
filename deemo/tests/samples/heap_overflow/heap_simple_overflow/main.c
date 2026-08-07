/* heap_simple_overflow: trivial heap overflow.
   malloc(32), memcpy 256 bytes → clear overflow. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = malloc(32);
    if (!buf) return 1;
    memset(buf, 0, 256);  /* 224 byte overflow */
    free(buf);
    return 0;
}
