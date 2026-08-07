// CVE-2022-22620: Conditional free — free on one path, use on another
#include <stdlib.h>

int vuln_conditional_uaf(int err) {
    char *buf = (char*)malloc(256);       // @uaf_alloc
    if (err) {
        free(buf);                        // @uaf_free — path A: freed
        return -1;
    }
    // path B: buf is still valid, but static analysis merges with path A
    buf[0] = 'A';                         // @uaf_use — UAF on path A only
    free(buf);
    return 0;
}
int main() { vuln_conditional_uaf(0); vuln_conditional_uaf(1); return 0; }