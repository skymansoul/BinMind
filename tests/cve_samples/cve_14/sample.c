#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* CVE-2019-14287: heap overflow from integer wrapping in allocation size */
void alloc_wrap(int user_count) {
  unsigned int total = user_count * 8;
  char *buf = malloc(total);
  if (!buf) return;
  /* BUG: if user_count large enough, total wraps to small value,
     but loop writes user_count*8 bytes anyway — heap overflow */
  for (int i = 0; i < user_count; i++) {
    sprintf(buf + i*8, "%08x", i);
  }
  printf("buf: %s\n", buf);
  free(buf);
}
int main(int c, char**v) {
  alloc_wrap(c > 1 ? atoi(v[1]) : 5);
  return 0;
}
