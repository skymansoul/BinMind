/* UAF-22: Struct field alias — free struct, use via field pointer (TP) */
#include <stdlib.h>
#include <string.h>

struct container {
    char *data;
    int size;
};

void process(void) {
    struct container *c = (struct container *)malloc(sizeof(struct container));
    if (!c) return;
    c->data = (char *)malloc(256);
    if (!c->data) { free(c); return; }
    strcpy(c->data, "payload");
    char *alias = c->data;
    free(c->data);
    free(c);
    /* BUG: alias points to freed c->data */
    alias[0] = 'x';
}

int main(void) {
    process();
    return 0;
}
