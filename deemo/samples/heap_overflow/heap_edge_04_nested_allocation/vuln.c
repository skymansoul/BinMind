/* nested struct: inner buffer allocated separately, outer write overflows */
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    int length;
} Buffer;

void edge_nested_overflow(char *src) {
    Buffer *b = (Buffer *)malloc(sizeof(Buffer));
    b->data = (char *)malloc(64);
    b->length = 256;
    if (b->data) {
        memcpy(b->data, src, b->length);  /* 256 > 64 �� OVERFLOW */
    }
    free(b->data);
    free(b);
}

int main(void) {
    static char src[300];
    edge_nested_overflow(src);  /* length 256 > 64 */
    return 0;
}
