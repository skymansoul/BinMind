#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// uaf_double_free_variant: UAF via double free: ptr freed twice, second free triggers UAF on stale data
// Type: uaf
typedef struct obj { int id; void (*cb)(struct obj*); } obj_t;
int main() {
    obj_t *p = (obj_t*)malloc(sizeof(obj_t));
    p->id = 1; p->cb = NULL;
    // Vulnerability: free(p); free(p);
    free(p); free(p);;
    return 0;
}
