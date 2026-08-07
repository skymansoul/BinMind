/* 偏移写入溢出: buf+offset处写入溢出
 * 预期: 检测器追踪 offset+len > alloc_size
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char*)malloc(128);
    int offset = 100;
    /* 写入128字节但偏移100 → 超出32字节 */
    memcpy(buf + offset, "long_data_string_that_exceeds_remaining_buffer_space", 128);
    free(buf);
    return 0;
}
