/* UAF-24: Double free via alias — same object freed twice through different names (TP) */
#include <stdlib.h>
#include <string.h>

void process(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    char *alias = buf;
    free(buf);
    /* BUG: double free — alias still points to freed memory */
    free(alias);
}

int main(void) {
    process();
    return 0;
}
