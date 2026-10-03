/* 指针算术越界: p = arr; p[15] 访问超分配 */
#include <stdlib.h>
typedef struct { int h; } Hdr;
int main() {
    Hdr* arr = malloc(8 * sizeof(Hdr));
    Hdr* p = arr + 3;
    p[5].h = 42;   /* arr[8] 越界 */
    free(arr);
    return 0;
}
