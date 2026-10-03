// CVE-2016-0189: Realloc UAF — use old pointer after realloc
#include <stdlib.h>
#include <string.h>

int vuln_realloc_uaf() {
    char *old = (char*)malloc(64);        // @uaf_alloc
    strcpy(old, "data");
    char *new_ptr = (char*)realloc(old, 128);  // @uaf_realloc — may move
    // Bug: if realloc moved the block, old is dangling
    char c = old[0];                      // @uaf_use — UAF if moved
    if (new_ptr) free(new_ptr);
    return c;
}
int main() { vuln_realloc_uaf(); return 0; }