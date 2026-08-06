#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// safe_free_then_null: Safe: set pointer to NULL after free
// Type: safe
typedef struct obj { int id; void (*cb)(struct obj*); } obj_t;
int main() {
    obj_t *p = (obj_t*)malloc(sizeof(obj_t));
    p->id = 1; p->cb = NULL;
    // Vulnerability: free(p); p = NULL;
    free(p); p = NULL;;
    return 0;
}
