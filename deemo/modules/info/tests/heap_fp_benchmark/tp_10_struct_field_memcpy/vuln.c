/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
typedef struct { char name[8]; int flag; } rec_t;
int main(void) {
    char src[64];
    memset(src, 'H', sizeof(src));
    rec_t *r = (rec_t *)malloc(sizeof(rec_t));
    if (!r) return -1;
    memcpy(r->name, src, 64);
    free(r);
    return 0;
}
