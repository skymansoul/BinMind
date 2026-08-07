/* heap_struct_write: offset-based write into struct allocated on heap.
   Tests the struct field access detection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct record { int id; char name[48]; long timestamp; };
int main(void) {
    struct record *r = malloc(sizeof(*r));  /* ~60 bytes */
    if (!r) return 1;
    r->id = 1;
    memset(r->name, 'N', 48);
    r->timestamp = 0xdeadbeef;
    /* Accessing fields at expected offsets — SAFE */
    char *raw = (char*)r;
    raw[60] = '!';  /* at offset 60, likely within slack. borderline. */
    free(r);
    return 0;
}
