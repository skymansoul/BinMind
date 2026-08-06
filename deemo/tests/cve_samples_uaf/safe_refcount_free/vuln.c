#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// safe_refcount_free: Safe: free only when refcount reaches 0
// Type: safe
typedef struct obj { int id; void (*cb)(struct obj*); } obj_t;
int main() {
    obj_t *p = (obj_t*)malloc(sizeof(obj_t));
    p->id = 1; p->cb = NULL;
    // Vulnerability: if (--obj->refcount == 0) free(obj);
    if (--obj->refcount == 0) free(obj);;
    return 0;
}
