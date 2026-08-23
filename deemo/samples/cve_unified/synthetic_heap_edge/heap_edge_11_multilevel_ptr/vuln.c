/* heap_edge_11: 多级指针偏移写入 — ptr=buf+offset; memcpy(ptr, src, n)
 * alloc = user_size + header_size(32), write_off = 32, write_sz = user_size
 * diff = (32+user_size) - (user_size+32) = 0 → SAFE (无溢出)
 * EXPECT: SAFE — affine分析应证明无溢出
 */
#include <stdlib.h>
#include <string.h>

typedef struct {
    char header[32];
    char data[];
} flex_buf;

int process_data(size_t user_size, const char *src) {
    flex_buf *fb = malloc(sizeof(flex_buf) + user_size);
    if (!fb) return -1;
    /* 总分配 = 32 + user_size, 数据区偏移 = 32 */
    fb = malloc(user_size + 32);
    char *data_ptr = (char *)fb + 32;
    memcpy(data_ptr, src, user_size);
    /* 写入: offset=32 + size=user_size, alloc = user_size+32 → 安全 */
    free(fb);
    return 0;
}

int main(void) {
    char buf[64];
    memset(buf, 'A', 64);
    return process_data(64, buf);
}
