/* CWE-416: UAF in loop - free inside loop, use after loop */
#include <stdio.h>
#include <stdlib.h>
typedef struct node { int id; struct node *next; } Node;
int main(void) {
    Node *head = malloc(sizeof(Node));
    head->id = 1; head->next = malloc(sizeof(Node));
    head->next->id = 2; head->next->next = NULL;
    Node *cur = head;
    while (cur) {
        Node *tmp = cur;
        cur = cur->next;
        if (tmp->id == 1) free(tmp);
    }
    printf("id=%d\n", head->id); /* UAF: head was freed when id==1 */
    return 0;
}
