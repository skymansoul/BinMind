/* CWE-122: multiple malloc with size confusion */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(char *short_str, char *long_str) {
    size_t len_s = strlen(short_str);
    size_t len_l = strlen(long_str);
    char *a = malloc(len_s);
    char *b = malloc(len_l);
    memcpy(a, long_str, len_l);  /* copy long into short buffer */
    memcpy(b, short_str, len_s);
    printf("a=%s b=%s\n", a, b);
    free(a); free(b);
}
int main(int argc, char **argv) {
    if (argc < 3) return 1;
    process(argv[1], argv[2]);
    return 0;
}
