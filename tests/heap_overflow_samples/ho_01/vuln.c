/* CVE-2021-3156 CWE-787: malloc未预留转义扩展空间导致溢出 */
#include <stdlib.h>
#include <string.h>
char* escape(const char* s) {
    char* b = malloc(strlen(s)+1); char* p = b;
    for (; *s; s++) { if (*s=='\\') *p++='\\'; *p++=*s; }
    *p=0; return b;
}
int main(int c, char** v) { char* p=escape(c>1?v[1]:"\\t"); free(p); return 0; }
