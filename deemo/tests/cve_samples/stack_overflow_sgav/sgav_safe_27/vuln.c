/* SAFE: memmove 使用 sizeof(buf) 限制 */
#include <string.h>
void safe_move(const char *src) {
    char buf[64];
    memmove(buf, src, sizeof(buf) - 1);
}
int main() { safe_move("test"); return 0; }
