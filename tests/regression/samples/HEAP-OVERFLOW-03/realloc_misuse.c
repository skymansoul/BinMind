#include <stdlib.h>
#include <string.h>
/* realloc misuse: using old size after growth */
void grow_buffer(char **p, int *psz, int new_sz) {
  *p=realloc(*p, new_sz);
  memset(*p+*psz, 0, new_sz-*psz);  /* uses old size if realloc failed */
  *psz=new_sz;
}
int main() { int sz=64; char *p=malloc(sz);
  grow_buffer(&p,&sz,256); free(p); return 0; }