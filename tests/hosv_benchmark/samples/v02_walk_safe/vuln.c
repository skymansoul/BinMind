/* SAFE - 指针游走有界: malloc(strlen*2+1) 预留扩展空间 */
#include <stdlib.h>
#include <string.h>
char* escape_ok(const char* s) {
    size_t l = strlen(s);
    char* b = malloc(l * 2 + 2);
    char* p = b;
    for (const char* q = s; *q; q++) {
        if (*q == '\\') { *p++ = '\\'; }
        *p++ = *q;
    }
    *p = 0;
    return b;
}
int main(int c, char** v) {
    char* p = escape_ok(c > 1 ? v[1] : "\\t");
    free(p);
    return 0;
}
