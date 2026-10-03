/* UAF-18: Conditional free with guard-protected use — same guard condition (SAFE) */
#include <stdlib.h>
#include <string.h>

void process(int error) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    if (error) {
        free(buf);
        buf = NULL;
        return;
    }
    /* SAFE: error path already returned */
    buf[0] = 'x';
    free(buf);
}

int main(void) {
    process(0);
    process(1);
    return 0;
}
