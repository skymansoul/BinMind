#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* CVE-2018-11235: heap overflow via off-by-one in git submodule name parsing */
char *parse_submodule(const char *input) {
  int len = strlen(input);
  char *name = malloc(len); /* BUG: no +1 for null terminator */
  memcpy(name, input, len + 1); /* writes len+1 into len-sized buffer = overflow */
  return name;
}
int main(int c, char**v) {
  char *result = parse_submodule(v[1] ? v[1] : "test_submodule_name");
  printf("parsed: %s\n", result);
  free(result);
  return 0;
}
