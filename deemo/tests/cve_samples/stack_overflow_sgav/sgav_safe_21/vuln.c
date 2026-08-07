/* SAFE: fgets 限制读取长度 */
#include <stdio.h>
void safe_read() {
    char buf[32];
    fgets(buf, sizeof(buf), stdin);
}
int main() { safe_read(); return 0; }
