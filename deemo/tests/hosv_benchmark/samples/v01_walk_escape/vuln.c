/* CVE-2021-3156 (sudo) - malloc(strlen) 无 +1, *p++ 双步游走 */
#include <stdlib.h>
#include <string.h>
char* escape(const char* s) {
    size_t l = strlen(s);
    char* b = malloc(l + 1);
    char* p = b;
    for (const char* q = s; *q; q++) {
        if (*q == '\\') { *p++ = '\\'; }
        *p++ = *q;
    }
    *p = 0;
    return b;
}
int main(int c, char** v) {
    char* p = escape(c > 1 ? v[1] : "\\t");
    free(p);
    return 0;
}
