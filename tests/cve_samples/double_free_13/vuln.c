/* double_free_13 — 异常安全缺失(C++模拟) */
#include <stdio.h>
#include <stdlib.h>
char*resource=NULL;
void acquire(){resource=malloc(256);}
void release(){if(resource){free(resource);}}
int main(){acquire();release();release();return 0;}
