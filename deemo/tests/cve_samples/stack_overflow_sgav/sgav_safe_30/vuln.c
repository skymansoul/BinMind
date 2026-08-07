/* SAFE: read 限制读取大小 */
#include <unistd.h>
void safe_read() {
    char buf[64];
    read(0, buf, sizeof(buf) - 1);
}
int main() { safe_read(); return 0; }
