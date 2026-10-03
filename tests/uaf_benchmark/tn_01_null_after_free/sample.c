/* TN-01: NULL After Free (SAFE) */
#include <stdlib.h>
#include <stdio.h>
void null_after_free(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    free(buf);
    buf = NULL;
    if (buf != NULL) { printf("%s\n", buf); }
}
int main(void) { null_after_free(); return 0; }