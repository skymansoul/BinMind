#include <stdio.h>
/* FMT-14: 内联常量 — fprintf(stderr, "const") 是安全的 */
int main(void) {
    fprintf(stdout, "constant format string\n");  /* SAFE */
    fprintf(stdout, "value: %d\n", 42);  /* SAFE */
    return 0;
}
