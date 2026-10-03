/* memcpy 长度由外部提供且超分配 */
#include <stdlib.h>
#include <string.h>
int main(int c, char** v) {
    char* b = malloc(8);
    size_t n = c > 1 ? (size_t)atoi(v[1]) : 32;
    memcpy(b, "payload-beyond-eight-bytes", n);
    free(b);
    return 0;
}
