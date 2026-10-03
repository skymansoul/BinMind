/* 守卫上限超过分配容量: if(n<=100) 但 malloc(50*sizeof) */
#include <stdlib.h>
#include <stdio.h>
typedef struct { int v; } Elem;
int main() {
    int n = 0;
    scanf("%d", &n);
    if (n <= 100) {
        Elem* a = malloc(50 * sizeof(Elem));
        for (int i = 0; i < n; i++) a[i].v = i;
        free(a);
    }
    return 0;
}
