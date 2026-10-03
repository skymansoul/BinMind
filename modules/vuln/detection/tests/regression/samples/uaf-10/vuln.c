/* UAF-10: 循环中free后重用 */
#include <stdlib.h>
#include <string.h>
int main() {
  for(int i=0;i<3;i++){char*p=malloc(64);free(p);if(i==2)strcpy(p,"uaf");}
  return 0;
}
