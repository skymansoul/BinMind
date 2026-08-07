/* CVE-2019-13139 Docker: integer overflow in memory allocation for string.
 * len + 1 may overflow → small allocation for path string.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
char *duplicate_path(const char *path) {
    int len = (int)strlen(path);
    if (len < 0 || len > 0x7FFFFFFE) return NULL;
    char *copy = (char*)malloc(len + 1); /* len=0x7FFFFFFF → len+1 wraps */
    if (!copy) return NULL;
    memcpy(copy, path, len);
    copy[len] = '\0';
    return copy;
}
