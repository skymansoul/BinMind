/* UAF-8: 链表节点删除后遍历 */
#include <stdlib.h>
struct node { int v; struct node *n; };
int main() {
  struct node *a=malloc(sizeof(struct node)),*b=malloc(sizeof(struct node));
  a->n=b; b->n=NULL; free(b);
  for(struct node *c=a;c;c=c->n) { /* BUG: c->n指向已释放的b */ }
  free(a); return 0;
}
