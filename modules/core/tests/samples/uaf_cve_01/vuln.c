// CVE-2021-38000: Direct UAF — free then use
#include <stdlib.h>
#include <string.h>

typedef struct { int len; char *data; } Buf;

int vuln_direct_uaf() {
    Buf *p = (Buf*)malloc(sizeof(Buf));  // @uaf_alloc
    p->len = 64;
    p->data = (char*)malloc(64);
    free(p);                              // @uaf_free — p is freed
    // Missing: p = NULL;
    int n = p->len;                       // @uaf_use — UAF: p is dangling
    return n;
}
int main() { vuln_direct_uaf(); return 0; }