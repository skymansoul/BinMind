/* double_free_11 — C++析构函数等价(手动模拟) */
#include <stdio.h>
#include <stdlib.h>
typedef struct{char*d1;char*d2;}Container;
void destroy(Container*c){free(c->d1);free(c->d2);free(c);}
int main(){Container*c=malloc(sizeof(Container));c->d1=malloc(32);c->d2=c->d1;destroy(c);return 0;}
