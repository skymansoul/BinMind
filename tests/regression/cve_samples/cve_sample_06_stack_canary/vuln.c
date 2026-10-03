/* CVE-mimic: Stack overflow with canary (tests canary detection)
 * Compile: gcc -fstack-protector -o vuln vuln.c
 */
#include <stdio.h>
#include <string.h>
void vuln(char *input) {
    char buf[32];
    strcpy(buf, input);  /* overflow detectable, canary present */
    printf("%s
", buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    vuln(argv[1]);
    return 0;
}