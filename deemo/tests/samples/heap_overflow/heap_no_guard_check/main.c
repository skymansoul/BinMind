/* heap_no_guard_check: NO guard condition before overflowing write.
   This should be detected with HIGH confidence. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = malloc(32);
    if (!buf) return 1;
    /* No bounds check before the write */
    memset(buf, 0, 128);  /* clear overflow, no guard */
    free(buf);
    return 0;
}
