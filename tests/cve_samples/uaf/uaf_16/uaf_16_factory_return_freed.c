/* UAF-16: Factory function returns freed pointer — callee frees and returns dangling ptr (TP) */
#include <stdlib.h>
#include <string.h>

char *create_and_free(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return NULL;
    strcpy(buf, "data");
    free(buf);
    /* BUG: returns freed pointer */
    return buf;
}

void process(void) {
    char *p = create_and_free();
    /* BUG: p is dangling */
    p[0] = 'x';
}

int main(void) {
    process();
    return 0;
}
