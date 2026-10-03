/* CVE-2015-0235 — GHOST: glibc gethostbyname buffer overflow
   Type: buffer_overflow (heap)
   gcc -O0 ghost.c -o ghost

   The original bug was in __nss_hostname_digits_dots() which used
   a fixed-size buffer on the stack and could be overflowed via
   crafted DNS response. This is a simplified demonstration. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DNS_MAX 1024
static char dns_buffer[DNS_MAX];

/* VULNERABLE: copies hostname without length check */
int vulnerable_gethost(char *hostname) {
    char tmpbuf[64];
    /* BUG: no size check on hostname before strcpy */
    strcpy(tmpbuf, hostname);  /* stack overflow if hostname > 63 bytes */
    printf("Looking up: %s\n", tmpbuf);
    return 0;
}

int main(int argc, char **argv) {
    char *input = (argc > 1) ? argv[1] : "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    vulnerable_gethost(input);
    return 0;
}
