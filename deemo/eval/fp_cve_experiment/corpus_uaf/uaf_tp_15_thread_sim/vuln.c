/* UAF-TP-15: worker(p) 在 release(p) 之后解引用 p. */
#include <stdlib.h>
#include <stdio.h>

void release(char *p) { free(p); }
void worker(char *p) { p[0] = 'W'; }

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    release(p);
    worker(p);
    printf("%c\n", p[0]);
    return 0;
}
