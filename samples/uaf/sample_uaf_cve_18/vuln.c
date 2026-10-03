/* CVE-2023-0669 GitLab: realloc old-pointer UAF.
 * Pattern: realloc may move; writing through old pointer is UAF.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    if (!p) return 1;
    strcpy(p, "data");
    char *old = p;
    free(p);
    strcpy(old, "UAF_WRITE");
    return 0;
}
