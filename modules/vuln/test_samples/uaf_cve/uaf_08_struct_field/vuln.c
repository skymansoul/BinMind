/* uaf_08_struct_field — free 后写结构体字段 (TP)。
 * Expected: UAF */
#include <stdlib.h>

typedef struct { int a; int b; } S;

int main(void) {
    S *s = (S *)malloc(sizeof(S));
    if (!s) return 1;
    free(s);
    s->a = 42;                    /* UAF write to field */
    return 0;
}
