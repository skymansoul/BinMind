#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    printf("[*] %d\n", buf[0]);
    free(buf);                       /* 之后不再使用 */
    return 0;
}
