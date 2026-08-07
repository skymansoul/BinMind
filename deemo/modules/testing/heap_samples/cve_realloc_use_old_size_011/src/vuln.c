/* realloc to smaller size, then memmove with old larger size */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    size_t old_sz = 256, new_sz = argc > 1 ? (size_t)atoi(argv[1]) : 64;
    char *buf = (char *)malloc(old_sz);
    if (!buf) return 1;
    memset(buf, 'A', old_sz);
    buf = (char *)realloc(buf, new_sz);
    memmove(buf + 10, buf, old_sz - 10);  /* BUG: old_sz > new_sz */
    printf("[*] buf[0]='%c'\n", buf[0]);
    free(buf);
    return 0;
}
