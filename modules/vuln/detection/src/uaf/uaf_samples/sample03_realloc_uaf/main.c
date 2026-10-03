#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *old = (char *)malloc(32);
    if (!old) return 1;
    strcpy(old, "data");
    /* realloc may free old and return new block */
    char *new_buf = (char *)realloc(old, 64);
    if (new_buf) {
        /* UAF: old pointer still used */
        old[0] = 'X';
        printf("old=%s new=%s\n", old, new_buf);
    }
    free(new_buf);
    return 0;
}
