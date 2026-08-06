/* integer-overflow-06: 整数溢出导致过小分配
 * 类型: integer overflow → heap overflow
 */
#include <stdlib.h>
#include <string.h>
void copy_data(unsigned short count, char *src) {
    unsigned int total = count * 256;  /* BUG: unsigned short*256可能溢出 */
    char *buf = malloc(total);
    memcpy(buf, src, count * 256);
    free(buf);
}
int main() { char s[1024]; copy_data(300, s); return 0; }
