#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

void vuln(const char *in) {
  char b[256];
  strncpy(b,in,255);b[255]=0;
  syslog(LOG_INFO,b); /* BUG: fmt string */
}
int main(int c,char**v){
  if(c<2)return 1;
  vuln(v[1]);
  return 0;
}
