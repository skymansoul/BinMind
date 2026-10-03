/* chain of reallocs with stale size reference */
#include <stdlib.h>
#include <string.h>

void edge_realloc_chain(char *data) {
    int sz = 128;
    char *buf = (char *)malloc(sz);
    buf = (char *)realloc(buf, 64);
    buf = (char *)realloc(buf, 32);
    if (buf) {
        memcpy(buf, data, sz);  /* 128 > 32 �� OVERFLOW */
        free(buf);
    }
}

int main(void) {
    static char data[200];
    edge_realloc_chain(data);  /* sz=128 > 32 */
    return 0;
}
