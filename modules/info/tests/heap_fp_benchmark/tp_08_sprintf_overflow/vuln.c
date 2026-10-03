/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    sprintf(buf, "%s-%s-%s", "AAAAAAAA", "BBBBBBBB", "CCCCCCCCCCCCCC");
    free(buf);
    return 0;
}
