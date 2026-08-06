/* CVE-2016-0728 — Linux keyring stack overflow / CWE-121 */
#include <string.h>
void keyring_read(char *data, int dlen) {
    char buf[128];
    memcpy(buf, data, dlen); /* BUG: dlen unchecked against sizeof(buf) */
}
int main(void) { char d[256]; memset(d,'C',256); keyring_read(d,256); return 0; }
