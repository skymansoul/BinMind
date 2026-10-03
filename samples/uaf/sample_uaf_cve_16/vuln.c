/* CVE-2021-38001 V8 Turbofan: alias-chain UAF.
 * Pattern: q = p; free(p); use(q) — alias passes through free.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(256);
    if (!p) return 1;
    strcpy(p, "sensitive");
    char *q = p;
    free(p);
    strcpy(q, "UAF_WRITE");
    return 0;
}
