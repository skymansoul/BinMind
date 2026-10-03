/* GENERIC-offbyone-loop CWE-787: for i<=n 导致一次越界写入 */
#include <stdlib.h>
typedef struct { int h; char d[64]; } I;
I* alloc(int n) { I* b=malloc(n*sizeof(I)); for(int i=0;i<=n;i++)b[i].h=i; return b; }
int main() { I* p=alloc(10); free(p); return 0; }
