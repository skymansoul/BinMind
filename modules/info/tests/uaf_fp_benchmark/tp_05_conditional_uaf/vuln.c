/* UAF TP sample */
#include <stdlib.h>
#include <stdio.h>
typedef struct { int v; } obj_t;
int main(int argc, char **argv) {
    int flag = argc > 1 ? atoi(argv[1]) : 0;
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    if (flag) { free(p); }
    p->v = 5;
    return 0;
}
