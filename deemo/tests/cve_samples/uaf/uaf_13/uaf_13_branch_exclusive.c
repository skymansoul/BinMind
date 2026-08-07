/* UAF-13: Mutually-exclusive branches — free and use in different paths (TN/FP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(int mode) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "data");

    if (mode == 0) {
        free(buf);
        /* In this branch, buf is freed and NOT used */
    } else {
        /* SAFE: use only in non-free branch — free() unreachable here */
        printf("mode=%d: %s\n", mode, buf);
        free(buf);  /* proper cleanup in this branch */
    }
    /* No UAF: free and use are in mutually exclusive branches */
}

int main(void) {
    process(1);
    return 0;
}
