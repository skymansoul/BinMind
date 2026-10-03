/* UAF-TP-14: req 释放后, 其内嵌回调数据被读取. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    int kind;
    char payload[8];
} req_t;

int main(void) {
    req_t *req = (req_t *)malloc(sizeof(req_t));
    if (!req) return 1;
    req->kind = 7;
    memset(req->payload, 'p', 8);
    free(req);
    req->kind = 9;
    printf("%d\n", req->kind);
    return 0;
}
