/* Signed→unsigned conversion => negative becomes huge */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int process(const char *data, int signed_len) {
    if (signed_len <= 0) return -1;
    if (signed_len > 4096) return -1;
    size_t len = (size_t)signed_len;
    char *buf = (char *)malloc(len);
    if (!buf) return -1;
    memcpy(buf, data, len);
    free(buf);
    return 0;
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 16;
    process("testdata", n);
    return 0;
}
