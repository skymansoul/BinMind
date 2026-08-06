#include <stdlib.h>
#include <string.h>
/* Integer wrap leads to small allocation, then large copy */
void *wrap_alloc(int n, int sz) {
  int total=n*sz;
  if(total>4096) return NULL;
  char *p=malloc(total);
  memcpy(p,(char*)&n, n*sz);  /* total passed check but n*sz may overflow */
  return p;
}
int main() { char x=0; wrap_alloc(65536,65); return 0; }