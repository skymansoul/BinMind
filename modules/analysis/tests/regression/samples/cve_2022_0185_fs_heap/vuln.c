#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_opt(const char *input) {
    char buf[64];
    size_t len = strlen(input);
    memcpy(buf, input, len); /* BUG: no bounds check */
    buf[63]=0; printf("opt: %s", buf);
}
int main(int a, char **v) { if(a<2) return 1;
    parse_opt(v[1]); return 0; }