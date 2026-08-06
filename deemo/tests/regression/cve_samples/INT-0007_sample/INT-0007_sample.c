/* INT-007: Shift overflow in size calculation */
#include <stdlib.h>
void alloc_array(int count) {
    size_t sz = count << 2; /* count*4 via shift */
    char *p = malloc(sz);   /* BUG: count<<2 may overflow */
    free(p);
}
int main(void) { alloc_array(1073741824); return 0; }
