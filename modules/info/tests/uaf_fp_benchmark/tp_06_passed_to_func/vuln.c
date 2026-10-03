/* UAF TP sample */
#include <stdlib.h>
#include <stdio.h>
typedef struct { int v; } obj_t;
static void print_obj(obj_t *o) { printf("%d", o->v); }
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    print_obj(p);
    return 0;
}
