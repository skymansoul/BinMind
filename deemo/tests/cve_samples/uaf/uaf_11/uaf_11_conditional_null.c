/* UAF-11: Conditional free WITH NULL — safe pattern (TN/FP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(int flag) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "data");

    if (flag) {
        free(buf);
        buf = NULL;  /* SAFE: nullified on the free path */
    }
    /* On free path: buf is NULL, safe
     * On non-free path: buf is still valid, safe */
    if (buf) {
        printf("%s\n", buf);
        free(buf);
    }
}

int main(void) {
    process(1);
    process(0);
    return 0;
}
