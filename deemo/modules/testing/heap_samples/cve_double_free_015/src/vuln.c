/* Double-free vulnerability */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "test data");
    free(buf);
    /* ... many lines of code ... */
    free(buf);  /* BUG: double free */
    printf("[*] done\n");
    return 0;
}
