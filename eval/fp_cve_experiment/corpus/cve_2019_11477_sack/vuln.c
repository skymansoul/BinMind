/* CVE-2019-11477: SACK 段数累加(seq 偏移叠加)超过
 * 分配区, 溢出写入 skb 数据区.
 */
#include <stdlib.h>
#include <string.h>

#define MAX_SACK 64

int parse_sack(unsigned char *skb, int skb_len,
               unsigned short *starts, int nseg) {
    if (nseg > MAX_SACK) return -1;
    int off = 0;
    for (int i = 0; i < nseg; i++) {
        off += starts[i];
        if (off < 0) off = 0;
        skb[off] = 0x01;
    }
    return off;
}

int main(int argc, char **argv) {
    (void)argc;
    unsigned char *skb = (unsigned char *)malloc(256);
    unsigned short starts[MAX_SACK];
    if (!skb) return 1;
    memset(skb, 0, 256);
    for (int i = 0; i < MAX_SACK; i++) starts[i] = 100;
    parse_sack(skb, 256, starts, MAX_SACK);
    free(skb);
    return 0;
}
