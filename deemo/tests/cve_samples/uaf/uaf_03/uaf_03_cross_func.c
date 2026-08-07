/* UAF-03: Cross-function UAF via global pointer (TP) */
#include <stdlib.h>
#include <stdio.h>

static char *g_buf = NULL;

void alloc_buffer(void) {
    g_buf = (char *)malloc(256);
}

void free_buffer(void) {
    free(g_buf);
    /* BUG: g_buf not set to NULL after free */
}

void use_buffer(void) {
    if (g_buf) {
        /* UAF: g_buf may have been freed by free_buffer() */
        printf("%s\n", g_buf);
    }
}

int main(void) {
    alloc_buffer();
    free_buffer();
    use_buffer();  /* cross-function UAF */
    return 0;
}
