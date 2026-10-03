#include <stdio.h>
#include <stdlib.h>

typedef struct Node {
    int val;
    struct Node *next;
} Node;

int main(void) {
    Node *head = (Node *)malloc(sizeof(Node));
    Node *mid = (Node *)malloc(sizeof(Node));
    Node *tail = (Node *)malloc(sizeof(Node));
    if (!head || !mid || !tail) return 1;
    head->val = 1; head->next = mid;
    mid->val = 2; mid->next = tail;
    tail->val = 3; tail->next = NULL;
    free(mid);
    /* UAF: head->next is freed mid */
    printf("skipped free node: %d\n", head->next->val);
    free(head);
    free(tail);
    return 0;
}
