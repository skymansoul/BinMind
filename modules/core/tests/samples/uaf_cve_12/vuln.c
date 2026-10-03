// SAFE-002: Safe pattern — correct temporal order
#include <stdlib.h>

typedef struct { int x; } Data;

int safe_use_before_free() {
    Data *d = (Data*)malloc(sizeof(Data));  // @alloc
    d->x = 100;
    int result = d->x;                      // @use — before free, safe
    free(d);                                // @free
    return result;                          // no dangling access
}
int main() { safe_use_before_free(); return 0; }