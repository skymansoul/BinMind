/* malloc(strlen) 缺 +1, d[l]=0 越界 */
#include <stdlib.h>
#include <string.h>
char* dup(const char* s) {
    size_t l = strlen(s);
    char* d = malloc(l);
    memcpy(d, s, l);
    d[l] = 0;
    return d;
}
int main(int c, char** v) {
    char* p = dup(c > 1 ? v[1] : "t");
    free(p);
    return 0;
}
