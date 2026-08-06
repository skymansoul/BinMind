/* CVE-2014-0160: OpenSSL Heartbleed — 堆越界读 (简化演示版) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void dtls1_process_heartbeat(unsigned char *p, unsigned int payload_len) {
    unsigned int declared = (p[0]<<8)|p[1];
    unsigned char *resp = malloc(declared+3);
    /* BUG: declared 来自攻击者, 未校验 declared <= payload_len */
    memcpy(resp+3, p+2, declared);
    printf("%s\n", resp+3);
    free(resp);
}
int main() { unsigned char p[]={0xFF,0xFF,'A','B'}; dtls1_process_heartbeat(p,2); return 0; }
