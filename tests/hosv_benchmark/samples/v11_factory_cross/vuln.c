/* 工厂函数返回小缓冲 + 跨函数 strcpy 溢出 */
#include <stdlib.h>
#include <string.h>
void* make_buf(int n) {
    return malloc(n);
}
int main(int c, char** v) {
    char* p = (char*)make_buf(16);
    strcpy(p, c > 1 ? v[1] : "overflow-data-payload");
    free(p);
    return 0;
}
