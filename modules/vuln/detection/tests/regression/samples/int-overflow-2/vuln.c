/* INT-2: 加法溢出→越界偏移
 * CWE-190, Ground Truth: 无符号加法溢出导致指针回绕
 */
#include <stdlib.h>
#include <string.h>
void patch(unsigned int off, unsigned int len, char *data) {
    char *buf = malloc(4096);
    /* BUG: off+len若>UINT_MAX→wrap around→写入意外位置 */
    memcpy(buf + off, data, len);
    free(buf);
}
int main() { patch(0xFFFFFF00, 512, "AAAA"); return 0; }
