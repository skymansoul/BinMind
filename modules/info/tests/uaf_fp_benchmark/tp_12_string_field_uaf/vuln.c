/* UAF TP sample */
#include <stdlib.h>
#include <string.h>
typedef struct { char *name; } rec_t;
int main(void) {
    rec_t *s = (rec_t *)malloc(sizeof(rec_t));
    if (!s) return -1;
    s->name = (char *)malloc(32);
    free(s);
    if (s->name[0]) { return 1; }
    return 0;
}
