/* SAFE: memcpy 写入大小(16) < 缓冲区(32) */
#include <string.h>
void safe_copy(const char *src) {
    char buf[32];
    memcpy(buf, src, 16);
}
int main() { safe_copy("hello"); return 0; }
