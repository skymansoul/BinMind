/* heap_int_overflow_to_heap: integer overflow → undersized allocation → heap overflow.
   count * sizeof(T) wraps around → small malloc → large memcpy.
   Tests integer overflow to heap overflow chaining. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned int count = 0x40000001;  /* > 1 billion, *4 wraps to 4 */
    int *buf = malloc(count * sizeof(int));  /* allocates only 4 bytes! */
    if (!buf) return 1;
    memset(buf, 0, count * sizeof(int));  /* actual write far exceeds alloc */
    free(buf);
    return 0;
}
