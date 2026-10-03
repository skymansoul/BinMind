#include <stdlib.h>
#include <string.h>
/* Loop-based heap overflow ¡ª write past buffer end */
void fill_table(int *table, int nrows) {
  table=malloc(nrows*sizeof(int)*2);
  for(int i=0;i<nrows*3;i++) table[i]=i;  /* overflow: nrows*3 > allocated nrows*2 */
  free(table);
}
int main() { int *t=0; fill_table(t,10); return 0; }