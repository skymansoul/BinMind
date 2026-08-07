/* HEAP-OVERFLOW-COND-03: overflow only under specific condition.
   Tests flow-sensitive analysis. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = malloc(32);
    if (!buf) return 1;
    int sz = 32;
    if (argc > 1) {
        sz = 128;  /* conditionally oversized */
    }
    memset(buf, 0, sz);  /* overflow when sz=128 */
    free(buf);
    return 0;
}
