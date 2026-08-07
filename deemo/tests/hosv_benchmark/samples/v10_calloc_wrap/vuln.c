/* calloc 整数回绕: 65536*65536 溢出 */
#include <stdlib.h>
#include <string.h>
void* mat(int r, int c) {
    return calloc(r, c);
}
int main() {
    char* p = (char*)mat(65536, 65536);
    if (p) { strcpy(p, "t"); }
    free(p);
    return 0;
}
