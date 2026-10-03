#include <stdio.h>
#include <stdlib.h>
struct node { int val; struct node *next; };
void remove_node(struct node **head, int val) {
struct node *cur = *head, *prev = NULL;
while (cur) { if (cur->val == val) {
if (prev) prev->next = cur->next; else *head = cur->next; free(cur); }
prev = cur; cur = cur->next; } }
int main() { struct node *n = malloc(sizeof(*n)); n->val=1; n->next=NULL;
remove_node(&n,1); return 0; }
