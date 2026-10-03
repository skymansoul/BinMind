/* CVE-mimic: Stack off-by-one overflow (null byte overwrite)
 * Real CVE: CVE-2017-1000253 (PIE stack clash)
 * Compile: gcc -fno-stack-protector -o vuln vuln.c
 */
#include <stdio.h>
#include <string.h>
void vuln(char *input) {
    char buf[64];
    int i;
    for (i = 0; i <= 64 && input[i]; i++) buf[i] = input[i];  /* off-by-one */
    buf[i] = 0;
    printf("%s
", buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    vuln(argv[1]);
    return 0;
}