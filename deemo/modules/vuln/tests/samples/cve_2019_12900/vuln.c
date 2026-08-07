/* CVE-2019-12900 — bzip2 解压缩越界写 (堆溢出)
 *
 * 触发条件: BZ2_decompress 中 out->buf 的分配基于压缩头中的大小字段,
 * 攻击者可构造恶意的压缩头使声明的大小小于实际解压出的数据量。
 *
 * 测试目标: 值域分析应检测到解压大小与分配大小的不一致。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct bz_stream {
    char *next_out;
    unsigned int avail_out;
    unsigned int total_out_lo32;
};

static int bz_decompress(struct bz_stream *strm, unsigned int declared_size) {
    unsigned int actual_out;

    strm->next_out = (char *)malloc(declared_size);
    if (!strm->next_out) return -1;

    /* 模拟: 实际输出超过声明大小 */
    actual_out = declared_size + 256;  /* 恶意压缩数据导致超额输出 */

    /* BUG: actual_out > allocated declared_size */
    memset(strm->next_out, 'A', actual_out);
    strm->total_out_lo32 = actual_out;

    free(strm->next_out);
    return 0;
}

int main(int argc, char **argv) {
    struct bz_stream strm = {0};
    unsigned int sz;
    if (argc < 2) return 1;
    sz = (unsigned int)atoi(argv[1]);
    bz_decompress(&strm, sz);
    return 0;
}
