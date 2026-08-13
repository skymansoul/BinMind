#include <stdlib.h>
__attribute__((noinline)) void release_only(void) {
    char *p = malloc(16);
    if (!p) return;
    p[0] = 1;
    free(p);
}
int main(void){ release_only(); return 0; }
