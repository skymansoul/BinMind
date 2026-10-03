/* 结构体字段安全: malloc(sizeof(struct))+write fields
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
typedef struct { int a; int b; char buf[56]; } data_t;
int struct_safe() {
    data_t *d = malloc(sizeof(data_t));
    if (!d) return -1;
    d->a = 1;
    d->b = 2;
    memcpy(d->buf, src, 56);
    free(d);
    return 0;
}
