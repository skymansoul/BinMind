/* UAF-001: Genuine use-after-free — free then use without NULL assignment */
#include <stdlib.h>
#include <stdio.h>
void process(void) {
    char *buf = malloc(128);
    free(buf);
    printf("%s", buf); /* UAF: buf used after free */
}
int main(void) { process(); return 0; }
