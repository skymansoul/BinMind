/* SAFE - malloc(strlen+1) 预留终止符 */
#include <stdlib.h>
#include <string.h>
char* dup_ok(const char* s) {
    size_t l = strlen(s);
    char* d = malloc(l + 1);
    memcpy(d, s, l);
    d[l] = 0;
    return d;
}
int main(int c, char** v) {
    char* p = dup_ok(c > 1 ? v[1] : "t");
    free(p);
    return 0;
}
