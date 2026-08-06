#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void debug_log(const char*f,const char*m){
  fprintf(stderr,m); /* BUG: fmt string */
}
int main(int c,char**v){
  if(c<2)return 1;
  debug_log("auth",v[1]);
  return 0;
}
