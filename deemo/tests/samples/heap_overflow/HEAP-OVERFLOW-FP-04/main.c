/* HEAP-OVERFLOW-FP-04: SAFE code that naive detectors flag as overflow.
   malloc(128), writes at offset 100 (within bounds). MUST be filtered.
   Tests the slack-space and value-range analysis. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct header { int id; int flags; char name[48]; };
struct body { long key; char data[64]; };
int main(void) {
    struct body *b = malloc(sizeof(*b));  /* ~72 bytes */
    if (!b) return 1;
    b->key = 0x1234;
    memset(b->data, 'F', 64);  /* write at offset 8, size 64 = ends at 72. SAFE */
    printf("body key=%ld\n", b->key);
    free(b);
    return 0;
}
