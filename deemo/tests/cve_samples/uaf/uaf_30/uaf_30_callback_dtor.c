/* UAF-30: Callback registration frees then use — function pointer frees (TP) */
#include <stdlib.h>
#include <string.h>

typedef void (*destructor_fn)(void *);

void destroy(void *p) {
    free(p);
}

void process(void) {
    char *obj = (char *)malloc(128);
    if (!obj) return;
    destructor_fn dtor = destroy;
    dtor(obj);
    /* BUG: obj freed via function pointer callback */
    obj[0] = 'x';
}

int main(void) {
    process();
    return 0;
}
