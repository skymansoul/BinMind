/* CVE-mimic: Heap buffer overflow via malloc+memcpy with wrong size
 * Real CVE: CVE-2021-3156 (sudo heap overflow)
 * Compile: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(char *input, int len) {
    char *buf = malloc(32);
    memcpy(buf, input, len);  /* overflow if len > 32 */
    printf("Processed: %s
", buf);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1], strlen(argv[1]));
    return 0;
}