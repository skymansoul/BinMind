/* TP-04: Realloc Alias UAF (CWE-416, CVE-2023-28328 class) */
#include <stdlib.h>
#include <string.h>
typedef struct { int len; char data[64]; } buf_t;
void realloc_alias_uaf(void) {
    buf_t *p = (buf_t *)malloc(sizeof(buf_t));
    if (!p) return;
    p->len = 64;
    buf_t *q = p;
    p = (buf_t *)realloc(p, 128);
    memset(q->data, 0, 64);  /* UAF: q dangling after realloc */
}
int main(void) { realloc_alias_uaf(); return 0; }