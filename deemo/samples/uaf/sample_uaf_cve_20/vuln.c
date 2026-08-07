/* CVE-2015-3864 Android Stagefright: error-path free.
 * Pattern: free on error path, strcpy use on normal path.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *meta = malloc(1024);
    if (!meta) return 1;
    strcpy(meta, "mp4_data");
    free(meta);
    strcpy(meta, "UAF_WRITE");
    return 0;
}
