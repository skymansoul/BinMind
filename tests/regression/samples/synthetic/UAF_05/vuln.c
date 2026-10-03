/* CWE-416: UAF via realloc(ptr,0) which equals free(ptr) */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *buf = malloc(128);
    snprintf(buf, 128, "test data");
    buf = realloc(buf, 0); /* realloc(ptr,0) is free */
    printf("buf=%s\n", buf); /* UAF: buf was freed by realloc */
    return 0;
}
