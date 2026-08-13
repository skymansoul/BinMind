/* CVE-2022-23222: eBPF verifier 对指针加偏移的验证缺失,
 * 用户可控偏移可越过对象边界写入.
 */
#include <stdlib.h>
#include <string.h>

struct map {
    int key;
    unsigned char data[32];
};

int bpf_write(struct map *m, int off, unsigned char v) {
    if (off < 0) return -1;
    m->data[off] = v;
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    struct map *m = (struct map *)malloc(sizeof(struct map));
    if (!m) return 1;
    memset(m, 0, sizeof(struct map));
    bpf_write(m, 64, 0xff);
    free(m);
    return 0;
}
