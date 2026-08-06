#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* CVE-2015-0235 GHOST: heap overflow via unchecked realloc */
void process_host(char *name, int extra) {
  char *buf = malloc(64);
  int needed = strlen(name) + extra;
  buf = realloc(buf, needed); /* BUG: needed may be 0, but realloc(ptr,0)=free */
  memcpy(buf, name, strlen(name)+1); /* overflow if realloc failed silently */
  printf("host: %s\n", buf);
  free(buf);
}
int main(int c, char**v) {
  process_host(v[1]?v[1]:"localhost", c>2?atoi(v[2]):4096);
  return 0;
}