/* CVE-2021-22555 — Linux netfilter xt_compat stack overflow / CWE-121 */
#include <string.h>
#include <stdlib.h>
void compat_match(void *user, int ulen) {
    char local[32];
    memcpy(local, user, ulen); /* BUG: 32 < ulen (up to 0xFFFF) */
}
int main(void) { char *u = malloc(64); memset(u,'H',64); compat_match(u,64); free(u); return 0; }
