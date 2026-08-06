#include <stdlib.h>
/* UAF via realloc shrink */
int main() { char *p=malloc(256); char *q=realloc(p,64);
  if(p!=q) p[0]='x'; free(q); return 0; }