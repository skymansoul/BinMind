#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX 128
void copy_line(const char*s){
  char line[MAX];int i;
  for(i=0;i<=MAX&&s[i]!=0&&s[i]!=10;i++)line[i]=s[i]; /* BUG: <= writes line[128] */
  line[i]=0;
  printf("line:%s\n",line);
}
int main(int c,char**v){
  char t[256];memset(t,0x42,256);t[255]=0;
  copy_line(t);
  return 0;
}
