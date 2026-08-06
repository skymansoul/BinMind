#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *data; int len; } Buffer;

void process(char *input) {
    Buffer *b = malloc(sizeof(Buffer));
    b->data = strdup(input);
    b->len = strlen(input);
    printf("len=%d\n", b->len);
    free(b->data);
    free(b);
    printf("freed=%s\n", b->data);  // UAF: b 已被释放
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
