/* SAFE - 工厂返回足够缓冲 + 有界拷贝 */
#include <stdlib.h>
#include <string.h>
void* make_buf(int n) {
    return malloc(n);
}
int main(int c, char** v) {
    char* p = (char*)make_buf(128);
    strncpy(p, c > 1 ? v[1] : "hi", 63);
    p[63] = 0;
    free(p);
    return 0;
}
