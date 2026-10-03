#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    int *vec = (int *)malloc(sizeof(int) * 2);
    if (!vec) return 1;
    vec[0] = 10; vec[1] = 20;
    int *old_ptr = &vec[1];  /* points into vec */
    /* realloc vec — old_ptr may become dangling */
    int *new_vec = (int *)realloc(vec, sizeof(int) * 8);
    if (new_vec) {
        vec = new_vec;
        /* UAF: old_ptr still points to old allocation */
        *old_ptr = 99;
        printf("stale ref: %d\n", *old_ptr);
    }
    free(vec);
    return 0;
}
