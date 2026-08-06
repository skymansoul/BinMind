#include <stdlib.h>
/* Double free leading to UAF */
int main() { char *p=malloc(128); free(p); free(p); /* double free */
  char *q=malloc(128); p[0]='x'; /* p and q may alias */ return 0; }