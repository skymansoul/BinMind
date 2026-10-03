/* CVE-2019-9213 — Linux kernel mmap stack overflow / CWE-121 */
#include <string.h>
void expand_stack_vma(char *data, int len) {
    char buf[128];
    memcpy(buf, data, len); /* BUG: len from user, no check */
}
int main(void) { char d[256]; memset(d,'F',256); expand_stack_vma(d,256); return 0; }
