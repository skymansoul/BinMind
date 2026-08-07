/* CVE-2020-0796 SMBGhost: refcount double-free leading to UAF.
 * Pattern: premature free via refcount bug, then use.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *shared = malloc(256);
    if (!shared) return 1;
    strcpy(shared, "refcount_data");
    free(shared);
    free(shared);
    strcpy(shared, "UAF_WRITE");
    return 0;
}
