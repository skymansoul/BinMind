#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* CVE-2020-10713 BootHole: heap overflow in GRUB2 config parser */
void parse_config_line(const char *line) {
  int alloc_sz = 128;
  char *value = malloc(alloc_sz);
  if (!value) return;
  int copy_len = strlen(line);
  /* BUG: if copy_len > 128, memcpy writes beyond malloc'd buffer */
  if (copy_len > alloc_sz) {
    memcpy(value, line, copy_len); /* heap overflow */
  } else {
    memcpy(value, line, copy_len);
  }
  printf("value: %s\n", value);
  free(value);
}
int main(int c, char**v) {
  parse_config_line(v[1] ? v[1] : "key=short_value");
  return 0;
}
