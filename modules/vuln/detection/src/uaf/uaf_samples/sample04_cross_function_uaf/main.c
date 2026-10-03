#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void use_buffer(char *p) {
    p[0] = 'U';  /* UAF: p already freed by caller */
    printf("used: %c\n", p[0]);
}

int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "cross_function");
    free(buf);
    use_buffer(buf);  /* UAF: pass freed ptr to function */
    return 0;
}
