#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 100000;
    char *buf = (char *)malloc(n * 4); /* n=100000 → 400000 正常 */
    if (!buf) return 1;
    buf[0] = 'X';                      /* 固定小写入 */
    buf[1] = '\0';
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
