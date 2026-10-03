/* CVE-2021-3156: Sudo heap-based buffer overflow (Baron Samedit)
 * Simplified reproduction: heap buffer allocated based on user input
 * then filled with more data than allocated — classic heap overflow
 * Compile: gcc -o vuln vuln.c -no-pie -fno-stack-protector
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_input(const char *user_data, int user_len) {
    /* BUG: allocates user_len bytes but writes user_len + 16 bytes */
    char *buf = (char *)malloc(user_len);
    if (!buf) return;
    memcpy(buf, user_data, user_len); /* heap overflow: write exceeds allocation if user_len > allocated */
    /* Trigger: user_data contains more bytes than user_len claims */
    printf("processed: %s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: %s <input>\n", argv[0]); return 1; }
    int len = atoi(argv[1]);
    char data[256];
    memset(data, 'A', sizeof(data));
    process_input(data, len);
    return 0;
}
