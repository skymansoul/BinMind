/* CVE-2017-1000253: realpath 中 malloc(n) 后复制 n+1 字节
 * (含NUL), 单字节堆溢出.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *my_realpath(const char *path) {
    size_t n = strlen(path);
    char *r = (char *)malloc(n);
    if (!r) return 0;
    memcpy(r, path, n + 1);
    return r;
}

int main(int argc, char **argv) {
    char p[64];
    memset(p, 'C', 63);
    p[63] = 0;
    if (argc > 1) {
        strcpy(p, "/tmp/long/path/name/here");
    }
    char *r = my_realpath(p);
    printf("%d\n", r[0]);
    free(r);
    return 0;
}
