#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void proc(char *input) {
    char *a1 = malloc(128); char *a2 = a1;
    memcpy(a1, input, 128);
    free(a2); /* BUG: a1 still references freed memory */
    printf("out: %s", a1); /* UAF */
}
int main(int a, char **v) { char d[128]; memset(d, 'C', 128); proc(d); return 0; }