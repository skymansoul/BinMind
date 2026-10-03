/* UAF-21: Goto-based cleanup — free in error label, then fall through to use (TP) */
#include <stdlib.h>
#include <string.h>

void process(int error) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    if (error) goto cleanup;
    strcpy(buf, "data");
    buf[0] = 'o';
    return;
cleanup:
    free(buf);
    /* BUG: use after goto cleanup */
    buf[0] = 'x';
}

int main(void) {
    process(0);
    process(1);
    return 0;
}
