// CVE-2020-15999: Double free — second free on dangling pointer
#include <stdlib.h>

void vuln_double_free(void *ptr) {
    free(ptr);      // @uaf_free_1 — first free
    free(ptr);      // @uaf_free_2 — DOUBLE FREE (UAF subclass)
    // Between the two frees, ptr is a dangling reference
}
int main() {
    void *p = malloc(128);  // @uaf_alloc
    vuln_double_free(p);
    return 0;
}