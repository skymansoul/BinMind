#include <string.h>
#include <stdlib.h>

void multi_alloc(const char *in) {
    char *small = malloc(128);
    char *big = malloc(1024);
    if (!small || !big) { free(small); free(big); return; }
    memcpy(big, in, 1024);   /* copy==big alloc → SAFE */
    free(small);
    free(big);
}

int main(void) {
    char data[1024];
    memset(data, 'O', 1024);
    multi_alloc(data);
    return 0;
}
