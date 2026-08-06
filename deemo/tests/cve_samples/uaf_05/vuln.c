/* uaf_05 — 链表节点释放后遍历
 * CWE-416: 释放链表节点后继续遍历next指针
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
typedef struct Node { int data; struct Node *next; } Node;
int main() {
    Node *head = malloc(sizeof(Node));
    head->data = 1; head->next = malloc(sizeof(Node));
    head->next->data = 2; head->next->next = NULL;
    Node *cur = head;
    free(head);
    printf("%d\n", cur->data); /* UAF: cur指向已释放的head */
    return 0;
}
