/* CWE-190: Integer overflow via nmemb*size in calloc wrappers.
   Custom alloc wrapper that multiplies without overflow check. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void *safe_alloc(size_t nmemb, size_t size) {
    return calloc(nmemb, size); /* no overflow check before calloc */
}
void process(int n, char *data) {
    char *buf = safe_alloc(n, 4);
    if (!buf) return;
    memcpy(buf, data, n * 4); /* n*4 may overflow, alloc may be small */
    printf("%s\n", buf);
    free(buf);
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 0x40000001;
    process(n, "AAAAAAAA");
    return 0;
}
