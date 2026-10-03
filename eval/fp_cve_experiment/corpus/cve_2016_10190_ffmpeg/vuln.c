/* CVE-2016-10190: 解析容器时 len 字段来自文件头,
 * 未与 buf_size 比较即 memcpy 进堆缓冲区.
 */
#include <stdlib.h>
#include <string.h>

int read_chunk(unsigned char *data, int data_len,
               unsigned char *out, int out_sz) {
    int len;
    len = (data[0] << 8) | data[1];
    if (len > data_len - 2) return -1;
    memcpy(out, data + 2, (size_t)len);
    return len;
}

int main(int argc, char **argv) {
    (void)argc;
    unsigned char *chunk = (unsigned char *)malloc(1024);
    unsigned char *out = (unsigned char *)malloc(256);
    if (!chunk || !out) return 1;
    memset(chunk, 0, 1024);
    chunk[0] = 0x01;
    chunk[1] = 0x01;
    read_chunk(chunk, 1024, out, 256);
    free(chunk);
    free(out);
    return 0;
}
