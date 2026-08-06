/* CVE-2017-7269 — IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow
   Type: buffer_overflow (stack)
   gcc -O0 iis_overflow.c -o iis_overflow

   Original: ScStoragePathFromUrl function in IIS 6.0 WebDAV service
   had a buffer overflow when processing PROPFIND requests with
   specially crafted If headers exceeding 65535 bytes. This simplified
   version shows an unbounded memcpy into a stack buffer. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define URL_MAX 128

/* VULNERABLE: trusts external length field without validation */
int process_webdav(const unsigned char *request, unsigned int body_len) {
    unsigned char url_buf[URL_MAX];
    unsigned int hdr_len;

    if (body_len < 4) return -1;

    /* BUG: hdr_len from attacker-controlled request body,
       no check against sizeof(url_buf) */
    hdr_len = (request[0] << 24) | (request[1] << 16) |
              (request[2] << 8)  | request[3];

    /* Overflow: hdr_len can be up to 0xFFFFFFFF, but url_buf is 128 bytes */
    memcpy(url_buf, request + 4, hdr_len);

    printf("Processed URL: %.*s\n", URL_MAX, url_buf);
    return 0;
}

int main() {
    /* Simulated malicious PROPFIND request */
    unsigned char request[300];
    request[0] = 0x00; request[1] = 0x00; request[2] = 0x01;
    request[3] = 0x00; /* body_len = 256, exceeds URL_MAX=128 */
    memset(request + 4, 'A', 256);
    process_webdav(request, 260);
    return 0;
}
