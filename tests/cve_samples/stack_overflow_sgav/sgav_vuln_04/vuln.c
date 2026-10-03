/* VULN: memcpy 写入大小(128) > 缓冲区(32) */
#include <string.h>
void vuln() {
    char buf[32];
    char src[128] = {0};
    memcpy(buf, src, 128);
}
int main() { vuln(); return 0; }
