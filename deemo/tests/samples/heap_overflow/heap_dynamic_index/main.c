/* heap_dynamic_index: overflow via user-controlled array index.
   Tests dynamic offset tracking. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int idx = argc > 1 ? atoi(argv[1]) : 50;
    char *buf = malloc(32);
    if (!buf) return 1;
    buf[idx] = 'A';  /* overflow when idx >= 32 */
    free(buf);
    return 0;
}
