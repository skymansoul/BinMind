/* cross_func_write: f(heap_ptr, sz) writes to heap via internal memset
 * Pattern: init_buffer(heap_buf, excessive_size) → overflow not visible inline
 */
#include <stdlib.h>
#include <string.h>

void init_buffer(char *buf, size_t sz) {
    memset(buf, 0, sz);
}

void copy_data(char *dst, const char *src, size_t n) {
    memcpy(dst, src, n);
}

int main(int argc, char **argv) {
    size_t user_size = atoi(argv[1]);
    size_t alloc_size = user_size;
    size_t write_size = user_size + 64;

    char *buf1 = malloc(alloc_size);
    if (!buf1) return 1;
    init_buffer(buf1, write_size);  // 写入 alloc_size+64 → 堆溢出

    char *buf2 = malloc(alloc_size);
    if (!buf2) return 1;
    copy_data(buf2, "safe_data", alloc_size);  // 写入alloc_size → 安全

    free(buf1);
    free(buf2);
    return 0;
}
