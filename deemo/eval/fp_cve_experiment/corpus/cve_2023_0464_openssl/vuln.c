/* CVE-2023-0464: X.509 policy 检查中 n = data_len - 1,
 * data_len=0 时 n 下溢为巨大值, memcpy 越过缓冲区.
 */
#include <stdlib.h>
#include <string.h>

int policy_check(const unsigned char *data, int data_len,
                 unsigned char *out, int out_sz) {
    int n = data_len - 1;
    if (n > out_sz) n = out_sz;
    memcpy(out, data, n);
    return n;
}

int main(int argc, char **argv) {
    (void)argc;
    unsigned char *out = (unsigned char *)malloc(128);
    if (!out) return 1;
    policy_check((const unsigned char *)"", 0, out, 128);
    free(out);
    return 0;
}
