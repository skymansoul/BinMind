#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* syslog not available on all platforms; use fprintf as equivalent fmt string sink */
void vuln(const char *in) {
  char b[256];
  strncpy(b,in,255);b[255]=0;
  fprintf(stderr, b); /* BUG: fmt string — equivalent to syslog fmt bug */
}
int main(int c,char**v){
  if(c<2)return 1;
  vuln(v[1]);
  return 0;
}
