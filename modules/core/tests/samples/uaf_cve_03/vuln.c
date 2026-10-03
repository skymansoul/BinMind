// CVE-2019-13720: UAF via alias — free original, use alias
#include <stdlib.h>

typedef struct node { int val; struct node *next; } Node;

int vuln_alias_uaf() {
    Node *p = (Node*)malloc(sizeof(Node));  // @uaf_alloc
    p->val = 42;
    Node *q = p;                             // q aliases p
    free(p);                                 // @uaf_free
    int v = q->val;                          // @uaf_use — UAF via alias q
    return v;
}
int main() { vuln_alias_uaf(); return 0; }