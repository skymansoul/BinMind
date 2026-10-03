/* UAF-26: Multi-level call chain — 3-function deep, leaf frees, top uses (TP) */
#include <stdlib.h>
#include <string.h>

void leaf_free(void *p) {
    free(p);
}

void mid_process(char *data) {
    leaf_free(data);
}

void top_handler(void) {
    char *obj = (char *)malloc(256);
    if (!obj) return;
    strcpy(obj, "important");
    mid_process(obj);
    /* BUG: obj freed deep in call chain */
    obj[0] = 'x';
}

int main(void) {
    top_handler();
    return 0;
}
