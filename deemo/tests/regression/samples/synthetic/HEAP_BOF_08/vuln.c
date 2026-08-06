/* CWE-122: Heap overflow via memmove with overlapping regions on heap */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    size_t sz = argc > 1 ? (size_t)atoi(argv[1]) : 16;
    char *buf = malloc(sz);
    if (!buf) return 1;
    memset(buf, 'B', sz);
    memmove(buf + 8, buf, sz); /* overlap: src+sz may exceed alloc */
    free(buf); return 0;
}
