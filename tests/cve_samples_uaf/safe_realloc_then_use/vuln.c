#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// safe_realloc_then_use: Safe: realloc updates pointer before use
// Type: safe
typedef struct obj { int id; void (*cb)(struct obj*); } obj_t;
int main() {
    obj_t *p = (obj_t*)malloc(sizeof(obj_t));
    p->id = 1; p->cb = NULL;
    // Vulnerability: p = realloc(p, 256); p->data = 42;
    p = realloc(p, 256); p->data = 42;;
    return 0;
}
