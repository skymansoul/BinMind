/* CVE-2018-6485 — glibc getcwd/realpath heap overflow (Integer overflow in malloc)
 * Pattern: n = strtoul(user_input); malloc(n * sizeof(element)) where n*sizeof overflows
 * Minimized: nmemb * size overflows → malloc(0) → later write overflows */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned long n = 0x100000001;  // n * 4 = 0x400000004 > UINT32_MAX
    unsigned long size = 4;
    unsigned long long prod = n * size;
    unsigned int truncated = (unsigned int)prod;  // = 4, allocates only 4 bytes
    char *buf = (char *)malloc(truncated);
    if (buf) {
        memset(buf, 0x41, (size_t)prod);  // writes 0x400000004 bytes → massive overflow
        printf("CVE-2018-6485: alloc=%u write=%llu\n", truncated, prod);
        free(buf);
    }
    return 0;
}
