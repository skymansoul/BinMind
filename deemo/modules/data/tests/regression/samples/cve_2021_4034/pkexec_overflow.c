/* CVE-2021-4034 — Polkit pkexec heap overflow (PwnKit)
   Type: heap_overflow / buffer_overflow
   gcc -O0 pkexec_overflow.c -o pkexec_overflow

   Original: pkexec did not validate argc, allowing argv[0]=NULL
   to trigger out-of-bounds write via g_find_program_in_path().
   Simplified: missing validation on heap allocation size vs write size. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vulnerable_pkexec(char *user_input, unsigned int input_len) {
    char *buffer;

    /* BUG: allocates input_len but writes input_len + 256 bytes */
    buffer = (char *)malloc(input_len);
    if (!buffer) return -1;

    memset(buffer, 0, input_len + 256);  /* heap overflow */
    memcpy(buffer, user_input, input_len);
    printf("Processed: %s\n", buffer);
    free(buffer);
    return 0;
}

int main() {
    char payload[128]; memset(payload, 'B', 127); payload[127] = '\0';
    vulnerable_pkexec(payload, 127);
    return 0;
}
