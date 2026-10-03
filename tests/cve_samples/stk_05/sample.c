#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* CVE-2013-2028: nginx chunked transfer stack overflow */
void parse_chunked(char *body, int blen) {
  char buf[512];
  int off = 0;
  while (off < blen) {
    int cl = strtol(body + off, NULL, 16);
    off += 4;
    memcpy(buf + off - 4, body + off, cl);
    off += cl + 2;
  }
  printf("%s\n", buf);
}
int main(void) {
  char b[1024];
  memset(b, 'A', 1024);
  strcpy(b, "FF\r\n");
  parse_chunked(b, 1024);
  return 0;
}
