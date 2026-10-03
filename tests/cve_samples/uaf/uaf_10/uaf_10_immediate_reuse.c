/* UAF-10: Immediate reuse after free — safe pattern, NOT a UAF (TN/FP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "old data");
    free(buf);
    /* SAFE: immediately reallocated — buf points to new valid memory */
    buf = (char *)malloc(256);
    strcpy(buf, "new data");
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    process();
    return 0;
}
