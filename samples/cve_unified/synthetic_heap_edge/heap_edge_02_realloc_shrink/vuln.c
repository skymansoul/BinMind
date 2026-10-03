/* realloc shrinks buffer, then write uses original size */
#include <stdlib.h>
#include <string.h>

void edge_realloc_shrink(char *data) {
    int orig_size = 256;
    char *buf = (char *)malloc(orig_size);
    char *newbuf = (char *)realloc(buf, 64);
    if (newbuf) {
        memcpy(newbuf, data, orig_size);  /* 256 > 64 �� OVERFLOW */
        free(newbuf);
    }
}

int main(void) {
    static char data[300];
    edge_realloc_shrink(data);  /* orig_size=256 > 64 */
    return 0;
}
