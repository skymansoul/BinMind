#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) void re_malloc(const char *in) {
    char *p = malloc(64);
    if (!p) return;
    free(p);
    p = malloc(128);
    if (!p) return;
    memcpy(p, in, 64);
    free(p);
}
int main(void){ char d[64]; memset(d, 'D', 64); re_malloc(d); return 0; }
