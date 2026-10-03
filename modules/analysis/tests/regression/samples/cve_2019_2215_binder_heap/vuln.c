/* CVE-2019-2215: Android Binder UAF leading to heap overflow primitive */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct binder_buffer { size_t data_size; size_t offsets_size; char data[]; };

void process_binder_transaction(size_t data_sz, size_t off_sz, const char *input) {
    /* BUG: allocation only considers data_sz, but offsets may point beyond */
    size_t alloc_sz = data_sz + off_sz + 32;
    if (alloc_sz > 0x100000) alloc_sz = 0x100000;
    struct binder_buffer *buf = (struct binder_buffer *)malloc(alloc_sz);
    if (!buf) return;
    buf->data_size = data_sz;
    buf->offsets_size = off_sz;
    /* 写入总数据量 = data_sz + off_sz, 而分配时只加了32不是off_sz */
    memcpy(buf->data, input, data_sz + off_sz);
    /* BUG: if (data_sz + off_sz) > (data_sz + 32), overflow occurs */
    free(buf);
}

int main(int argc, char **argv) {
    size_t ds = 1024, os = 1024;
    if (argc >= 3) { ds = (size_t)atol(argv[1]); os = (size_t)atol(argv[2]); }
    char *input = (char *)calloc(1, ds + os);
    if (input) { memset(input, 'B', ds + os); process_binder_transaction(ds, os, input); free(input); }
    printf("done\n");
    return 0;
}
