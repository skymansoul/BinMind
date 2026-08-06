/* CVE-2011-1473: OpenSSL DTLS ChangeCipherSpec heap overflow — 简化 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process_dtls_fragment(char *fragment, unsigned short declared_len) {
    char *buf = malloc(declared_len);
    /* BUG: declared_len 来自网络包，攻击者可控；未校验上界 */
    memcpy(buf, fragment, declared_len + 8);
    printf("Processed %u bytes\n", declared_len);
    free(buf);
}
int main() { process_dtls_fragment("AAAA", 65535); return 0; }
