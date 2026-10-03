/* heap-overflow-10: 无符号整数回绕→过小分配
 * Ground Truth: size-1在size=0时回绕→分配巨量内存或零字节
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void copy_with_wraparound(unsigned int size) {
    unsigned int adjusted = size - 1;  /* BUG: size=0 → adjusted=0xFFFFFFFF */
    char *buf = malloc(adjusted + 1);  /* 可能分配0或极小内存 */
    memset(buf, 'A', adjusted);        /* 若adjusted=overflow→小分配大写入 */
    free(buf);
}
int main() { copy_with_wraparound(0); return 0; }
