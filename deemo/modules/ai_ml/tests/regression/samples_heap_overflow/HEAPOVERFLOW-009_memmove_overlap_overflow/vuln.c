#include <string.h>
#include <stdlib.h>
/* memmove在堆缓冲区上的非法偏移 */
void memmove_offset_overflow(const char *data, int len, int offset) {
    char *buf = malloc(len);
    if (!buf) return;
    memcpy(buf, data, len);
    /* VULN: offset可使memmove写到buf之后 */
    memmove(buf + offset, buf, len);
    free(buf);
}
int main() {
    char data[128]; for(int i=0;i<128;i++) data[i]='N';
    memmove_offset_overflow(data, 64, 48); /* src=buf+48, dst=buf+48 → 64B copy从buf[48]开始→超出buf[64] */
    return 0;
}
