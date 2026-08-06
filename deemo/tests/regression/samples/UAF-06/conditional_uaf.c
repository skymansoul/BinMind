#include <stdlib.h>
/* Conditional UAF: free in one branch, use in another */
int main(int argc, char **argv) { char *p=malloc(256);
  if(argc>1) { free(p); }
  p[0]='x'; /* UAF if argc>1 */ return 0; }