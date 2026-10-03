/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
static char src[256];
static void write_to(char *dst) { memcpy(dst, src, 256); }
int main(void) {
    memset(src, 'I', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    write_to(buf);
    free(buf);
    return 0;
}
