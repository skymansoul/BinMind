/* CWE-122: loop-based accumulation overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(int argc, char **argv) {
    char *buf = malloc(128);
    if (!buf) return;
    buf[0] = '\0';
    for (int i = 0; i < argc; i++)
        strcat(buf, argv[i]);  /* cumulative overflow */
    printf("%s\n", buf);
    free(buf);
}
int main(int argc, char **argv) {
    process(argc, argv);
    return 0;
}
