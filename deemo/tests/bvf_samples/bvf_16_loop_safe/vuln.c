/* 循环安全: malloc(640)+for(i<10)memcpy(buf+i*64,64)
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
int loop_safe() {
    char *buf = malloc(640);
    if (!buf) return -1;
    int i;
    for (i = 0; i < 10; i++) {
        memcpy(buf + i * 64, src, 64);
    }
    free(buf);
    return 0;
}
