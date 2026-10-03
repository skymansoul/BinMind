#include <stdlib.h>
#include <string.h>
/* UAF via realloc returning new pointer */
int main() { char *p=malloc(64); char *q=realloc(p,128);
  p[0]='x'; /* old p invalid */ free(q); return 0; }