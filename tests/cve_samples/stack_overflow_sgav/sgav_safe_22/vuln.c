/* SAFE: 缓冲区足够大容纳所有 strcat */
#include <string.h>
int main() {
    char buf[256] = {0};
    strcat(buf, "hello ");
    strcat(buf, "world");
    return 0;
}
