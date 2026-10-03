/* CVE-2022-22620 WebKit: conditional-free UAF.
 * Pattern: free in conditional branch, use afterward.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = malloc(128);
    if (!buf) return 1;
    strcpy(buf, "init");
    int flag = 1;
    if (flag) {
        free(buf);
    }
    strcpy(buf, "UAF_WRITE");
    return 0;
}
