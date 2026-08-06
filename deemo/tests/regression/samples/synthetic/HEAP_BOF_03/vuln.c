/* CWE-122: malloc->strncpy with off-by-one
   Simulates CVE-2021-3156 (sudo heap overflow pattern) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(char *input) {
    size_t len = strlen(input);
    char *buf = malloc(len);  /* missing +1 for null */
    if (!buf) return;
    strncpy(buf, input, len);
    buf[len] = '\0';  /* off-by-one write */
    printf("%s\n", buf);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
