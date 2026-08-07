/* heap_guard_protected: SAFE — overflow-preventing guard condition exists.
   buf[idx]=val is guarded by if(idx < N) where N = alloc_size.
   MUST be filtered out as a false positive. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int idx = argc > 1 ? atoi(argv[1]) : 10;
    char *buf = malloc(32);
    if (!buf) return 1;
    if (idx < 32) {  /* GUARD: prevents overflow */
        buf[idx] = 'A';
    }
    printf("idx=%d\n", idx);
    free(buf);
    return 0;
}
