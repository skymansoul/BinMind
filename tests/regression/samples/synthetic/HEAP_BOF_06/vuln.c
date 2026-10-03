/* CWE-122: realloc growth overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(char *input) {
    size_t old_len = 32;
    char *buf = malloc(old_len);
    strncpy(buf, input, old_len - 1);
    buf = realloc(buf, 256);
    strncat(buf, input, old_len);  /* still uses old_len */
    printf("%s\n", buf);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
