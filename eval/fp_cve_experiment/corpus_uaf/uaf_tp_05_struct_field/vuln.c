/* UAF-TP-05: obj->buf free 后 obj->buf[0] 访问. */
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int id;
    char *buf;
} obj_t;

int main(void) {
    obj_t *o = (obj_t *)malloc(sizeof(obj_t));
    if (!o) return 1;
    o->id = 1;
    o->buf = (char *)malloc(8);
    if (!o->buf) return 1;
    o->buf[0] = 'A';
    free(o->buf);
    o->buf[0] = 'B';
    printf("%d %c\n", o->id, o->buf[0]);
    free(o);
    return 0;
}
