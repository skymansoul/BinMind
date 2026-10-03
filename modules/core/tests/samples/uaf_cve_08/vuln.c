// CVE-2021-30551: C++ delete UAF — vtable access after delete
#include <stdlib.h>

typedef struct obj {
    void (*vfunc)(struct obj*);
    int data;
} Obj;

void obj_method(Obj *self) {
    self->data = 42;                      // @uaf_use — virtual call on freed
}

int vuln_cpp_delete_uaf() {
    Obj *o = (Obj*)malloc(sizeof(Obj));   // @uaf_alloc
    o->vfunc = obj_method; o->data = 0;
    free(o);                              // @uaf_free (simulates delete)
    o->vfunc(o);                          // @uaf_use — vtable call on freed object
    return 0;
}
int main() { vuln_cpp_delete_uaf(); return 0; }