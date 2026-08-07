/* CVE-2022-3602 — OpenSSL 3.0 punycode decoder heap overflow
 * Pattern: punycode_decode → computed output size < actual expansion */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned input_len = 256;
    unsigned max_expansion = input_len * 4;  // punycode expansion estimate
    char *buf = (char *)malloc(max_expansion);
    if (buf) {
        unsigned actual = input_len * 5;  // actual expansion > estimate → overflow
        memset(buf, 0x41, actual);
        printf("CVE-2022-3602: alloc=%u write=%u\n", max_expansion, actual);
        free(buf);
    }
    return 0;
}
