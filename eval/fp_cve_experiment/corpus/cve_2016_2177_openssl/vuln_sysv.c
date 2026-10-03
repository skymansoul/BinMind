/* CVE-2016-2177: EVP_EncodeUpdate 对超长输入计算输出长度
 * 时整数溢出, 导致写入越过分配的输出缓冲区.
 * 建模: out=malloc(64), 输入 len=1000000, 逐字节写入不做边界约束.
 */
#include <stdlib.h>
#include <string.h>

int encode(const unsigned char *in, int len, char *out, int outsz) {
    int olen = ((len + 2) / 3) * 4;
    if (olen > outsz) return -1;
    for (int i = 0; i < len; i++) {
        out[i] = (char)(in[i] & 0x3f) + 'A';
    }
    return olen;
}

int main(int argc, char **argv) {
    (void)argc;
    int len = 1000000;
    unsigned char *in = (unsigned char *)malloc((size_t)len);
    char *out = (char *)malloc(64);
    if (!in || !out) return 1;
    memset(in, 0x41, (size_t)len);
    encode(in, len, out, 64);
    free(in);
    free(out);
    return 0;
}
