#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-09: 链表节点UAF — 节点被free后继续遍历 */
typedef struct Node { int id; char data[32]; struct Node *next; } Node;
int main(void) {
    Node *head = (Node *)malloc(sizeof(Node));
    head->id = 1; strcpy(head->data, "first");
    head->next = (Node *)malloc(sizeof(Node));
    head->next->id = 2; strcpy(head->next->data, "second");
    head->next->next = NULL;
    free(head->next);  /* 释放第二个节点 */
    Node *cur = head;
    while (cur) {
        printf("node %d: %s\n", cur->id, cur->data);
        cur = cur->next;  /* VULNERABLE: cur->next已释放 */
    }
    free(head);
    return 0;
}
