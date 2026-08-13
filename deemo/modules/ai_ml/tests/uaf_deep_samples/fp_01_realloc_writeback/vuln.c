#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) void grow(const char *in) {
    char *p = malloc(64);
    if (!p) return;
    p = realloc(p, 128);
    if (!p) return;
    memcpy(p, in, 128);
    free(p);
}
int main(void){ char d[128]; memset(d, 'A', 128); grow(d); return 0; }
