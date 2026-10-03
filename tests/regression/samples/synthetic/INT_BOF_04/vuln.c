/* CWE-190: Signed/unsigned confusion in size check.
   Negative int passed to size_t becomes huge → bypasses size check */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void copy_data(int len, char *src) {
    if (len > 1024) return; /* signed check */
    char *buf = malloc((size_t)len); /* negative→huge */
    if (!buf) return;
    memcpy(buf, src, len > 0 ? (size_t)len : 0);
    free(buf);
}
int main(int argc, char **argv) {
    copy_data(argc > 1 ? atoi(argv[1]) : -1, "data");
    return 0;
}
