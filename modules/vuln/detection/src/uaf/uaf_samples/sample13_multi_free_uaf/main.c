#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cleanup(char *a, char *b) {
    if (a) free(a);
    if (b) free(b);
}

int main(void) {
    char *x = (char *)malloc(64);
    char *y = (char *)malloc(64);
    if (!x || !y) {
        free(x); free(y);
        return 1;
    }
    strcpy(x, "error_path");
    /* x freed inside cleanup */
    cleanup(x, NULL);
    /* UAF: x freed but reused */
    printf("after cleanup: %s\n", x);
    free(y);
    return 0;
}
