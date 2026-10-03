/* UAF-12: Realloc-based reuse — safe pattern, NOT a UAF (TN/FP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "initial");
    /* SAFE: realloc handles the old pointer — buf may change address */
    char *newbuf = (char *)realloc(buf, 256);
    if (newbuf) {
        buf = newbuf;
        strcat(buf, " extended");
        printf("%s\n", buf);
    }
    free(buf);
}

int main(void) {
    process();
    return 0;
}
