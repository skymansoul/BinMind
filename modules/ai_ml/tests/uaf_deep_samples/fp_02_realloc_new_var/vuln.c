#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) void mv(const char *in) {
    char *p = malloc(64);
    if (!p) return;
    char *np = realloc(p, 128);
    if (!np) return;
    memcpy(np, in, 128);
    free(np);
}
int main(void){ char d[128]; memset(d, 'B', 128); mv(d); return 0; }
