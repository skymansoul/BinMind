/* 结构体字段溢出: malloc(sizeof(struct))+write 128B to buf[56]
 * Has vulnerability: True
 */
#include <stdlib.h>
#include <string.h>
typedef struct { int a; int b; char buf[56]; } data_t;
int struct_overflow() {
    data_t *d = malloc(sizeof(data_t));
    if (!d) return -1;
    d->a = 1;
    memcpy(d->buf, src, 128);
    free(d);
    return 0;
}
