#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char *data;
    int len;
} Buffer;

int main(void) {
    Buffer b;
    b.data = (char *)malloc(64);
    b.len = 64;
    if (!b.data) return 1;
    b.data[0] = 'A';
    free(b.data);
    /* UAF: access freed member through struct */
    b.data[0] = 'B';
    printf("freed field: %c\n", b.data[0]);
    return 0;
}
