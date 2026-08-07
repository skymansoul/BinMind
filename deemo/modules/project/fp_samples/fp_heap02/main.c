#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    static const char b64in[] = "QUJDREVGR0hJSktMTU5PUFFSU1RVVg==";
    size_t inlen = strlen(b64in);
    unsigned char *out = (unsigned char *)malloc(inlen);
    if (!out) return 1;
    size_t w = 0;
    for (size_t i = 0; i < inlen; i++) {
        out[w++] = (unsigned char)b64in[i];
        if (i % 3 == 2) out[w++] = 0x00;
    }
    printf("%zu\n", w);
    free(out);
    return 0;
}
