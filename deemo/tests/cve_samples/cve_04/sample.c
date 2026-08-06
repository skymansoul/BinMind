#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(const char*d,unsigned int l){
  char*b=malloc(l); /* should be l+1 */
  if(!b)return;
  memcpy(b,d,l);
  b[l-1]=0;
  printf("%s\n",b);
  free(b);
}
int main(void){
  process("AAAAAAAABBBBBBBBCCCCCCCC",32);
  return 0;
}
