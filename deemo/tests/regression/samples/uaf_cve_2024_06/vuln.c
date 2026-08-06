/* UAF linked list */
#include <stdio.h>
#include <stdlib.h>
struct node { int val; struct node *next; };
int main() { struct node *a=malloc(sizeof(*a)),*b=malloc(sizeof(*b)); a->next=b;b->next=NULL; free(b); struct node *cur=a; while(cur){printf("%d",cur->val);cur=cur->next;} return 0; }
