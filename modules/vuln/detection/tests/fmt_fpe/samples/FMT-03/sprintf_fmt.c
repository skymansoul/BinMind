
/* sprintf 格式串漏洞复现: 用户输入作格式串, 可写越界. */
#include <stdio.h>
#include <stdlib.h>

static char *fmt_sink(char *user) {
    char *out = malloc(64);
    sprintf(out, user);      /* 格式串 = 用户输入 */
    return out;
}

int main(int argc, char **argv) {
    free(fmt_sink(argv[1]));
    return 0;
}
