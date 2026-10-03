/* SAFE - 循环写量精确等于分配大小 */
#include <stdlib.h>
#include <string.h>
int main() {
    char* b = malloc(64);
    char* p = b;
    for (int i = 0; i < 4; i++) {
        memcpy(p, "XXXXXXXX", 16);
        p += 16;
    }
    free(b);
    return 0;
}
