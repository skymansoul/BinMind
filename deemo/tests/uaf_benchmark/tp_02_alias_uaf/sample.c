/* TP-02: Alias Use-After-Free (CWE-416) */
#include <stdlib.h>
typedef struct node { int id; struct node *next; } node_t;
void alias_uaf(void) {
    node_t *p = (node_t *)malloc(sizeof(node_t));
    if (!p) return;
    p->id = 42;
    node_t *q = p;
    free(p);
    q->id = 99;  /* UAF: q dangling */
}
int main(void) { alias_uaf(); return 0; }