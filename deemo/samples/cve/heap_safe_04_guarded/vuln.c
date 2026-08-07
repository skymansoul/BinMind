/* heap_safe_04: Guarded allocation with size check
 * SAFE: size = atoi(argv[1]); if(size>1024)size=1024; buf=malloc(size); memcpy(buf,src,size)
 * Pattern: user input constrained before allocation → safe by construction
 * Naive tools see malloc(atoi(...)) → FALSE POSITIVE
 * Our taint+constraint tracking sees the 1024 guard → correctly filtered
 * Expected: FALSE POSITIVE for naive tools, CORRECTLY FILTERED by ours
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int safe_guarded_alloc(int size, const char *input) {
    if (size > 1024) size = 1024;   // constraint: size ≤ 1024
    if (size < 0) size = 64;
    char *buf = (char *)malloc(size);
    if (!buf) return -1;
    memcpy(buf, input, size);        // write size == constrained alloc size → SAFE
    buf[size - 1] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    int sz = (argc > 1) ? atoi(argv[1]) : 100;
    char dummy[1025];
    memset(dummy, 'G', 1024);
    dummy[1024] = 0;
    return safe_guarded_alloc(sz, dummy);
}
