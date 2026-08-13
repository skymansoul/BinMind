#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) void clr(const char *in) {
    char *p = malloc(64);
    if (!p) return;
    memcpy(p, in, 8);
    free(p);
    p = 0;
    if (p) memcpy(p, in, 8);
}
int main(void){ char d[8]; memset(d, 'C', 8); clr(d); return 0; }
