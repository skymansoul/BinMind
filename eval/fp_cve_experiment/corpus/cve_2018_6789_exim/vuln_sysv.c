/* CVE-2018-6789: b64decode 按输入长度/4*3 计算输出,
 * 但解码时每4字节写3字节, 输入长度非4倍数时多写.
 */
#include <stdlib.h>
#include <string.h>

int b64decode(const unsigned char *in, int inlen, unsigned char *out) {
    int outlen = (inlen / 4) * 3;
    int oi = 0;
    for (int i = 0; i + 3 < inlen; i += 4) {
        out[oi++] = (unsigned char)((in[i] & 0x3f) << 2 | (in[i + 1] >> 4));
        out[oi++] = (unsigned char)((in[i + 1] & 0x0f) << 4 | (in[i + 2] >> 2));
        out[oi++] = (unsigned char)((in[i + 2] & 0x03) << 6 | in[i + 3]);
    }
    if (inlen % 4 == 1) {
        out[oi++] = in[inlen - 1];
    }
    return outlen;
}

int main(int argc, char **argv) {
    (void)argc;
    int n = 100;
    unsigned char *in = (unsigned char *)malloc(n);
    unsigned char *out = (unsigned char *)malloc((n / 4) * 3);
    if (!in || !out) return 1;
    memset(in, 0x3f, n);
    b64decode(in, n, out);
    free(in);
    free(out);
    return 0;
}
