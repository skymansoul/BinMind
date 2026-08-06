/* CVE-2016-4484 — cryptsetup initramfs shell escape
   Type: buffer_overflow / command_injection
   gcc -O0 shell_escape.c -o shell_escape -lcryptsetup

   Original: pressing Enter at LUKS password prompt 93 times dropped
   to root shell. This simplified version demonstrates unchecked
   password buffer handling. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS_MAX 512

static char password_buf[PASS_MAX];

/* VULNERABLE: reads unlimited input into fixed buffer */
int read_password() {
    char buf[64];
    int count = 0;

    printf("Enter LUKS passphrase: ");
    /* BUG: fgets with oversized input can still overflow stack buffer */
    while (1) {
        int c = getchar();
        if (c == '\n' || c == EOF) break;
        buf[count++] = (char)c;
        /* Missing: if (count >= sizeof(buf)) break; */
    }
    buf[count] = '\0';

    /* Copy to global buffer without size check */
    strcpy(password_buf, buf);  /* buffer overflow if count >= PASS_MAX */
    return count;
}

int main() {
    int len = read_password();
    printf("Password length: %d\n", len);
    return 0;
}
