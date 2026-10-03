/* heap_edge_12: 结构体字段memcpy — 嵌套结构中的堆写入
 * alloc = sizeof(container)=sizeof(header)+payload_buf=48+256=304
 * write = 512 to payload_buf → 溢出208字节
 * EXPECT: OVERFLOW — 写入超过结构体有效载荷区
 */
#include <stdlib.h>
#include <string.h>

#define HEADER_SIZE 48
#define PAYLOAD_MAX 256

typedef struct {
    int version;
    size_t length;
    char reserved[40];
} header_t;

typedef struct {
    header_t hdr;
    char payload[PAYLOAD_MAX];
} container_t;

int read_packet(size_t user_len, const char *src) {
    container_t *c = malloc(sizeof(container_t));
    if (!c) return -1;
    c->hdr.length = user_len;
    /* BUG: user_len可能>PAYLOAD_MAX, 但payload只有256字节 */
    memcpy(c->payload, src, user_len);
    free(c);
    return 0;
}

int main(void) {
    char oversized[512];  /* 超过PAYLOAD_MAX=256 */
    memset(oversized, 'B', 512);
    return read_packet(512, oversized);
}
