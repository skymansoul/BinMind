/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[128];
    memset(src, 'C', sizeof(src) - 1);
    src[sizeof(src) - 1] = '\0';
    char *buf = (char *)malloc(32);
    if (!buf) return -1;
    strcpy(buf, src);
    free(buf);
    return 0;
}
