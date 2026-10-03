#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    snprintf(buf, 64, "%d", argc);
    printf("value=%s\n", buf);       /* 格式串为字面量 */
    free(buf);
    return 0;
}
