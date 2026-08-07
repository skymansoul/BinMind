/* 循环内 memcpy 到推进指针: buf+n 累积越界 */
#include <stdlib.h>
#include <string.h>
int main() {
    char* b = malloc(64);
    char* p = b;
    for (int i = 0; i < 8; i++) {
        memcpy(p, "XXXX", 16);
        p += 16;
    }
    free(b);
    return 0;
}
