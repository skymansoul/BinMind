/* SAFE: memcpy 前有 if(n <= sizeof(buf)) 守卫 */
#include <string.h>
#include <stdlib.h>
void safe_copy(int n, const char *src) {
    char buf[32];
    if (n > 0 && n < 32) {
        memcpy(buf, src, n);
    }
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 16;
    safe_copy(n, "test");
    return 0;
}
