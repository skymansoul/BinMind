/* CVE-mimic: Large heap overflow via integer underflow in size calc
 * Real CVE: CVE-2019-11477 (TCP SACK panic)
 * Compile: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void fragment(char *data, int offset, int len) {
    char *buf = malloc(128);
    memcpy(buf + offset, data, len);  /* overflow if offset+len > 128 */
    printf("Fragment: %s
", buf);
    free(buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    fragment(argv[1], 100, strlen(argv[1]));
    return 0;
}