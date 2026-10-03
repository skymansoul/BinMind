#include <stdlib.h>
__attribute__((noinline)) int guarded(int ok) {
    char *p = malloc(16);
    if (!p) return -1;
    if (!ok) { free(p); return -2; }
    p[0] = 1;
    free(p);
    return 0;
}
int main(void){ guarded(1); guarded(0); return 0; }
