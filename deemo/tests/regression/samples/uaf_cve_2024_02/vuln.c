/* UAF-002: realloc缩小后仍用旧指针写入 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
    char *buf = malloc(256);
    memset(buf, 'A', 256);
    char *new_buf = realloc(buf, 64);  /* SHRINK: old buf freed */
    memcpy(buf, new_buf, 256);         /* UAF: buf is dangling */
    free(new_buf);
    return 0;
}
