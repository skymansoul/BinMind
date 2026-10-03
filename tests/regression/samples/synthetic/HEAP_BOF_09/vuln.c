/* CWE-122: Heap overflow via strcat into fixed heap buffer in loop */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = malloc(64); buf[0] = '\0';
    for (int i = 1; i < argc; i++) strcat(buf, argv[i]);
    puts(buf); free(buf); return 0;
}
