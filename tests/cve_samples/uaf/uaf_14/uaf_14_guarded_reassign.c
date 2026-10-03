/* UAF-14: Guarded free with reassignment — safe pattern (TN/FP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *create_fallback(void) {
    return strdup("fallback");
}

void process(int error) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "primary");

    if (error) {
        free(buf);
        buf = create_fallback();  /* SAFE: reassigned on free path */
    }
    /* buf is always valid here: either original or fallback */
    printf("result: %s\n", buf);
    free(buf);
}

int main(void) {
    process(1);
    return 0;
}
