/* CVE-mimic: Format string vulnerability via printf(user_input)
 * Real CVE examples: CVE-2012-0809 (sudo), CVE-2022-48303 (tar)
 * Compile: gcc -fno-stack-protector -no-pie -o vuln vuln.c
 */
#include <stdio.h>

void log_message(char *msg) {
    printf(msg);  /* format string bug -- user controls format */
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <msg>\n", argv[0]); return 1; }
    log_message(argv[1]);
    return 0;
}
