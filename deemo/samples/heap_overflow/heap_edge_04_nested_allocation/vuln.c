/* nested struct: inner buffer allocated separately, outer write overflows */
typedef struct {
    char *data;
    int length;
} Buffer;

void edge_nested_overflow(char *src) {
    Buffer *b = (Buffer *)malloc(sizeof(Buffer));
    b->data = (char *)malloc(64);
    b->length = 256;
    if (b->data) {
        memcpy(b->data, src, b->length);  /* 256 > 64 ¡ª OVERFLOW */
    }
    free(b->data);
    free(b);
}
