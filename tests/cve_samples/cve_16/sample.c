#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* CVE-2021-3156: heap overflow via concatenated args */
void process_args(int argc, char**argv) {
  int total=0;
  for(int i=0;i<argc;i++) total+=strlen(argv[i])+1;
  char*buf=malloc(total);/* should be total+1 */
  int off=0;
  for(int i=0;i<argc;i++) {
    int l=strlen(argv[i]);
    memcpy(buf+off,argv[i],l);/* overflow possible */
    off+=l; buf[off++]=' ';
  }
  buf[off]=0;
  printf("cmd: %s\n", buf);
  free(buf);
}
int main(int c,char**v){process_args(c-1,v+1);return 0;}