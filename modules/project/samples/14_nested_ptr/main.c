/* 样本14: 嵌套指针的溢出 — 通过中间结构体间接写入
 * 模式: 分配struct A, 其内部指针指向struct B, 溢出通过A→B链路写入
 * 为何有效: 测试检测器对嵌套指针结构的溯源能力
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct buffer_handle {
    char *data;
    size_t size;
};

int main(int argc, char **argv) {
    /* 分配handle结构 */
    struct buffer_handle *handle = (struct buffer_handle *)
        malloc(sizeof(struct buffer_handle));
    if (!handle) return 1;

    /* 分配实际数据缓冲区 — 仅64B */
    handle->data = (char *)malloc(64);
    handle->size = 64;

    /* 通过handle间接写入: handle->data + offset */
    char *ptr = handle->data;
    /* 漏洞: 通过ptr写入, 值超过handle->size */
    memset(ptr, 'N', 256);

    printf("allocated %zu, wrote 256 via nested ptr\n", handle->size);
    free(handle->data);
    free(handle);
    return 0;
}
