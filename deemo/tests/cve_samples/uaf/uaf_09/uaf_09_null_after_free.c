/* UAF-09: NULL-after-free — safe pattern, NOT a UAF (TN/FP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "data");
    free(buf);
    buf = NULL;  /* SAFE: pointer nullified after free */
    /* Not a UAF — NULL deref at worst, not dangling pointer use */
    if (buf) printf("%s\n", buf);
}

int main(void) {
    process();
    return 0;
}
