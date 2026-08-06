/* CVE-2015-7547 — glibc getaddrinfo stack overflow / CWE-121 */
#include <string.h>
#include <stdlib.h>
void dns_parse(char *response, int resp_len) {
    char buf[2048];
    if (resp_len > 0) memcpy(buf, response, resp_len); /* BUG: resp_len can exceed 2048 */
}
int main(void) { char *r = malloc(4096); memset(r,'B',4096); dns_parse(r,4096); free(r); return 0; }
