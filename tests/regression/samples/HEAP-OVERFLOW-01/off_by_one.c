#include <stdlib.h>
#include <string.h>
/* Off-by-one heap overflow ¡ª classic pattern */
void copy_with_off_by_one(char *src, int len) {
  char *buf=malloc(len);
  for(int i=0;i<=len;i++) buf[i]=src[i];  /* writes len+1 bytes */
  free(buf);
}
int main() { char s[64]; copy_with_off_by_one(s,64); return 0; }