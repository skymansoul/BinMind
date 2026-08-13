#include <stdlib.h>
typedef struct { int refs; char data[8]; } rc_t;
__attribute__((noinline)) void use_guarded(rc_t *o) {
    if (o->refs > 0) o->data[0] = 1;
}
__attribute__((noinline)) void release(rc_t *o) {
    if (--o->refs == 0) free(o);
}
int main(void) {
    rc_t *o = malloc(sizeof(rc_t));
    if (!o) return 0;
    o->refs = 1;
    use_guarded(o);
    release(o);
    return 0;
}
