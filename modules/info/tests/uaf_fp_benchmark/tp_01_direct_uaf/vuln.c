/* UAF TP sample */
#include <stdlib.h>
typedef struct { int flag; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    p->flag = 1;
    return 0;
}
