#include <string.h>
#include <stdlib.h>

typedef struct { char hdr[16]; char data[256]; } blob_t;

void fill_blob(const char *in) {
    blob_t *b = malloc(sizeof(blob_t));   /* 272 */
    if (!b) return;
    memcpy(b->data, in, 256);             /* 字段容量内 → SAFE */
    free(b);
}

int main(void) {
    char data[256];
    memset(data, 'M', 256);
    fill_blob(data);
    return 0;
}
