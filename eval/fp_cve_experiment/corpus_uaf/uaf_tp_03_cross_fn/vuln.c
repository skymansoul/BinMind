/* UAF-TP-03: free_fn(p) 后 use_fn(p) 解引用. */
#include <stdlib.h>
#include <stdio.h>

char *alloc_fn(void) { return (char *)malloc(64); }
void free_fn(char *p) { free(p); }
void use_fn(char *p) { p[0] = 'Z'; }

int main(void) {
    char *p = alloc_fn();
    if (!p) return 1;
    free_fn(p);
    use_fn(p);
    printf("%c\n", p[0]);
    return 0;
}
