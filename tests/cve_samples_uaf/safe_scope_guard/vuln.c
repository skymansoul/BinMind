#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// safe_scope_guard: Safe: free at end of scope, no further use
// Type: safe
typedef struct obj { int id; void (*cb)(struct obj*); } obj_t;
int main() {
    obj_t *p = (obj_t*)malloc(sizeof(obj_t));
    p->id = 1; p->cb = NULL;
    // Vulnerability: free(tmp); return;
    free(tmp); return;;
    return 0;
}
