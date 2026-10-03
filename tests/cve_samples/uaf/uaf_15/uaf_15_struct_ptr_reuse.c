/* UAF-15: Struct pointer with field-level free — free via struct field (TP/FP boundary) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char *payload;
    size_t len;
} Request;

Request *make_request(const char *data) {
    Request *req = (Request *)malloc(sizeof(Request));
    if (!req) return NULL;
    req->payload = strdup(data);
    req->len = strlen(data);
    return req;
}

void free_request(Request *req) {
    if (req) {
        free(req->payload);
        free(req);  /* free the struct itself */
    }
}

void process(const char *input) {
    Request *r = make_request(input);
    if (!r) return;
    free_request(r);
    /* BUG: r is dangling — accessing r->len after free */
    printf("processed %zu bytes\n", r->len);
}

int main(void) {
    process("test input data here");
    return 0;
}
