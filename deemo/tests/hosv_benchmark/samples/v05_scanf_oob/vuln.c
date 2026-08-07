/* 无界 scanf %s 到堆缓冲 */
#include <stdlib.h>
#include <stdio.h>
int main() {
    char* b = malloc(32);
    scanf("%s", b);
    free(b);
    return 0;
}
