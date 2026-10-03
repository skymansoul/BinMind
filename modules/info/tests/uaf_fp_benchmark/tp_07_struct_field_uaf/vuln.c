/* UAF TP sample */
#include <stdlib.h>
typedef struct { char *data; } container_t;
int main(void) {
    container_t *c = (container_t *)malloc(sizeof(container_t));
    if (!c) return -1;
    c->data = (char *)malloc(16);
    free(c);
    c->data[0] = 'A';
    return 0;
}
