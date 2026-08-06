#include <stdio.h>
#include <stdlib.h>

void alloc_and_free() {
    char *buf = malloc(256);
    if (!buf) return;
    snprintf(buf, 256, "test data");
    printf("buf=%s\n", buf);
    free(buf);
    free(buf);  // double-free
}

int main() {
    alloc_and_free();
    return 0;
}
