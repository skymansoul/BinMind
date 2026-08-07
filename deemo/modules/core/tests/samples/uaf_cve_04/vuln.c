// CVE-2018-8174: UAF in loop
#include <stdlib.h>

typedef struct node { int val; struct node *next; } Node;

int vuln_loop_uaf() {
    Node *head = (Node*)malloc(sizeof(Node));  // @uaf_alloc
    head->val = 1; head->next = NULL;
    Node *cur = head;
    while (cur) {
        Node *tmp = cur;
        cur = cur->next;
        free(tmp);                              // @uaf_free — frees head
        // Bug: cur->next accessed AFTER free(tmp) where tmp==cur
        if (cur) cur->val += 1;                 // @uaf_use — UAF
    }
    return 0;
}
int main() { vuln_loop_uaf(); return 0; }