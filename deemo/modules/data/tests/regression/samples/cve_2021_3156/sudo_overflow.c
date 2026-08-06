/* CVE-2021-3156 — Sudo Baron Samedit heap overflow
   Type: heap_overflow
   gcc -O0 sudo_overflow.c -o sudo_overflow

   Original: sudoedit -s with escaped backslash caused heap overflow
   in set_cmnd(). This simplified version demonstrates heap buffer
   overflow from unvalidated user input length. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* VULNERABLE: allocates heap buffer based on user input,
   then writes more data than allocated */
int sudo_edit_mode(const char *user_args, int arg_len) {
    char *cmdline;

    /* BUG: allocates arg_len+1 bytes but concatenates two strings
       without checking total length */
    cmdline = (char *)malloc(arg_len + 1);
    if (!cmdline) return -1;

    strcpy(cmdline, "sudoedit ");
    /* Overflow: strcat adds up to arg_len more bytes, but cmdline
       is only arg_len+1 bytes and already has 9 bytes from "sudoedit " */
    strcat(cmdline, user_args);

    printf("Command: %s\n", cmdline);
    free(cmdline);
    return 0;
}

int main() {
    char payload[256];
    memset(payload, 'A', 255); payload[255] = '\0';
    sudo_edit_mode(payload, 255);
    return 0;
}
