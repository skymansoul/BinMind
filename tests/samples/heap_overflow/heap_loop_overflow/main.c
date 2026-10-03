/* heap_loop_overflow: overflow via loop bound miscalculation.
   Tests loop-bound inference in guard_condition_analyzer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 40;
    int *buf = malloc(16 * sizeof(int));  /* 64 bytes, 16 ints */
    if (!buf) return 1;
    for (int i = 0; i < n; i++) {
        buf[i] = i;  /* overflow when n > 16 */
    }
    printf("done\n");
    free(buf);
    return 0;
}
