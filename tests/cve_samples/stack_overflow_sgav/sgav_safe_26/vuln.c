/* SAFE: memset 使用 sizeof(buf) 限制 */
#include <string.h>
void safe_clear() {
    char buf[64];
    memset(buf, 0, sizeof(buf));
}
int main() { safe_clear(); return 0; }
