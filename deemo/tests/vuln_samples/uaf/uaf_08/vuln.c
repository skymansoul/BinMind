/* GENERIC-uaf-tree CWE-416: 树结构部分释放后访问子节点 */
#include <stdlib.h>
typedef struct T{int v;struct T*l,*r;}T;
T*mkt(int v){T*t=malloc(sizeof(T));t->v=v;t->l=t->r=0;return t;}
void fs(T*t){if(t){free(t);if(t->l)fs(t->l);}}
int main(){T*r=mkt(1);r->l=mkt(2);fs(r);return 0;}
