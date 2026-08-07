/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    scanf("%s", buf);
    free(buf);
    return 0;
}
