/* GENERIC-uaf-list CWE-416: 链表节点释放后遍历 */
#include <stdlib.h>
typedef struct N{int v;struct N*n;}N;
N*mk(int v){N*n=malloc(sizeof(N));n->v=v;n->n=0;return n;}
void fa(N*h){while(h){N*t=h->n;free(h);h=t;}}
int main(){N*a=mk(1);N*b=mk(2);a->n=b;fa(a);return 0;}
