/* UAF-28: Conditional free in nested if — free in inner block, use in outer scope (TP) */
#include <stdlib.h>
#include <string.h>

void process(int a, int b) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    if (a) {
        if (b) {
            free(buf);
        }
    }
    /* BUG: if a==1 && b==1, buf is freed */
    buf[0] = 'x';
}

int main(void) {
    process(0, 0);
    process(1, 1);
    return 0;
}
