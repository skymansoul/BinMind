/* 循环累积溢出: malloc(256)+for(i<10)memcpy(buf+i*64,64)
 * Has vulnerability: True
 */
#include <stdlib.h>
#include <string.h>
int loop_accum_overflow() {
    char *buf = malloc(256);
    if (!buf) return -1;
    int i;
    for (i = 0; i < 10; i++) {
        memcpy(buf + i * 64, src, 64);
    }
    free(buf);
    return 0;
}
