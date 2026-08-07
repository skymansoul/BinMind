/* INT-1: 乘法溢出→小分配→大写入
 * CWE-190, Ground Truth: unsigned short * 1024 → overflow→small alloc
 */
#include <stdlib.h>
#include <string.h>
void copy(unsigned short n, char *src) {
    size_t sz = n * 1024;  /* BUG: n=64时 64*1024=65536(overflow as ushort=0)→sz=0 */
    char *buf = malloc(sz+1);
    memcpy(buf, src, n * 1024);  /* 实际写入64KB, 但malloc可能只分配了1字节 */
    free(buf);
}
int main() { char s[65536]; copy(64, s); return 0; }
