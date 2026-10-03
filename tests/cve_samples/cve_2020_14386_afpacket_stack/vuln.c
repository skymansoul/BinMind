/* CVE-2020-14386 — Linux AF_PACKET stack overflow / CWE-121 */
#include <string.h>
void packet_setsockopt(char *optval, int optlen) {
    char buf[64];
    if (optlen < 0) return;
    memcpy(buf, optval, optlen); /* BUG: can copy up to INT_MAX */
}
int main(void) { char d[128]; memset(d,'G',128); packet_setsockopt(d,128); return 0; }
