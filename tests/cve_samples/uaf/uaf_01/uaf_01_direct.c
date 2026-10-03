/* UAF-01: Direct use-after-free — free then use without NULL assignment (TP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "sensitive data");
    free(buf);
    /* BUG: buf used after free — genuine UAF */
    printf("%s\n", buf);
}

int main(void) {
    process();
    return 0;
}
