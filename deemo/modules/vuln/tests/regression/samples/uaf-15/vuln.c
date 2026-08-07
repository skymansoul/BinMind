/* UAF-15: 多次分配中混淆释放顺序 */
#include <stdlib.h>
#include <string.h>
int main() {
  char *a=malloc(64),*b=malloc(64);
  free(a); memcpy(a,b,64); free(b);
  return 0;
}
