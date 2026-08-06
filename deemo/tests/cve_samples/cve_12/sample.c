#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* CVE-2016-4484: heap overflow in cryptsetup password handling */
void read_password(char *buf, int max_len) {
  char *tmp = malloc(max_len);
  /* BUG: copies max_len bytes but should be max_len-1 for null */
  memcpy(tmp, buf, max_len);
  printf("pass: %s\n", tmp);
  free(tmp);
}
int main(int c, char**v) {
  char data[256]; memset(data, 0x42, 256);
  read_password(data, c>1?atoi(v[1]):256);
  return 0;
}