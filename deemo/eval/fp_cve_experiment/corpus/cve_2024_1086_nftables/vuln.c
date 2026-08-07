/* CVE-2024-1086: nf_tables 批量删除时对象生命周期缺陷,
 * 复用释放对象进行越界写; 此处以等价的对象字段越界写建模.
 */
#include <stdlib.h>
#include <string.h>

struct nft_set {
    int genmask;
    unsigned char data[16];
    int len;
};

int nft_set_write(struct nft_set *s, const unsigned char *in, int in_len) {
    if (in_len > s->len) in_len = s->len;
    memcpy(s->data + s->len, in, in_len);
    s->len += in_len;
    return s->len;
}

int main(int argc, char **argv) {
    (void)argc;
    struct nft_set *s = (struct nft_set *)malloc(sizeof(struct nft_set));
    unsigned char in[32];
    if (!s) return 1;
    memset(s, 0, sizeof(struct nft_set));
    memset(in, 0xee, 32);
    s->len = 16;
    nft_set_write(s, in, 32);
    free(s);
    return 0;
}
