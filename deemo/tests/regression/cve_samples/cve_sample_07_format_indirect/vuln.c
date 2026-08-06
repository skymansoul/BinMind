/* CVE-mimic: Indirect format string via wrapper function
 * Compile: gcc -o vuln vuln.c
 */
#include <stdio.h>
void wrapper(char *fmt, char *arg) {
    printf(fmt, arg);  /* format string via wrapper -- fmt is user-controlled */
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    wrapper(argv[1], "test");
    return 0;
}