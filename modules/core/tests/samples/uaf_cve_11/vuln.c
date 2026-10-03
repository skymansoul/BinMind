// SAFE-001: Safe pattern — NULL assignment after free
#include <stdlib.h>

int safe_null_after_free() {
    int *p = (int*)malloc(sizeof(int));   // @alloc
    *p = 42;
    free(p);                              // @free
    p = NULL;                             // NULL assignment prevents UAF
    if (p) {
        *p = 0;                           // unreachable — p is NULL
    }
    return 0;
}
int main() { safe_null_after_free(); return 0; }