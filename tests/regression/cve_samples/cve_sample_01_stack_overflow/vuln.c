/* CVE-mimic: Stack buffer overflow via gets()
 * Reproduces pattern: fixed-size stack buffer + unbounded user input
 * Real CVE examples: CVE-2014-0160 (Heartbleed), CVE-2016-4484
 * Compile: gcc -fno-stack-protector -no-pie -o vuln vuln.c
 */
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buf[64];
    strcpy(buf, input);  /* no bounds check -- overflow if input > 64B */
    printf("Copied: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
