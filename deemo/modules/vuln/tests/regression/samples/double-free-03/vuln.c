/* double-free-03: 同一指针被释放两次
 * 类型: double-free
 */
#include <stdlib.h>
void cleanup(char *p) { free(p); free(p); /* BUG: double-free */ }
int main() { char *b = malloc(128); cleanup(b); return 0; }
