#include <stdlib.h>
/* UAF inside a loop */
int main() { char *items[5];
  for(int i=0;i<5;i++) { items[i]=malloc(64); free(items[i]); }
  items[2][0]='x'; return 0; }