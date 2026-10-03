#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    size_t len = argc > 1 ? strlen(argv[1]) : 8;
    char *buf = (char *)malloc(len + 1);  /* len+1, 无乘法 */
    if (!buf) return 1;
    strcpy(buf, argc > 1 ? argv[1] : "hello");
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
