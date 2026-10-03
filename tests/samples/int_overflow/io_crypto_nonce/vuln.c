#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-13: 加密nonce/计数器溢出 — 常用于流密码/CTR模式 */
int main(void) {
    unsigned int nonce = 0xFFFFFFF0u;
    char chunks[16][16];
    memset(chunks, 0, sizeof(chunks));
    for (unsigned int i = 0; i < 32; i++) {
        unsigned int ctr = nonce + i;  /* VULNERABLE: nonce+32回绕 */
        /* ctr循环使用, 同一nonce加密两个不同明文 — 密码学灾难 */
        if (ctr < 16) sprintf(chunks[ctr], "block_%u", ctr);
    }
    printf("chunk[0]=%s\n", chunks[0]);
    return 0;
}
