/* UAF TP sample */
#include <stdlib.h>
typedef struct node { struct node *next; int v; } node_t;
int main(void) {
    node_t *head = (node_t *)malloc(sizeof(node_t));
    if (!head) return -1;
    node_t *cur = head;
    free(head);
    while (cur) { cur = cur->next; }
    return 0;
}
