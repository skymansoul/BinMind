/* CVE-mimic: Double free vulnerability
 * Real CVE: CVE-2018-1000001 (glibc)
 * Compile: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void handler(char *data) {
    char *buf = strdup(data);
    printf("Got: %s
", buf);
    free(buf);
    free(buf);  /* double free */
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    handler(argv[1]);
    return 0;
}