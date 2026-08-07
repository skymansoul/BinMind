/* CVE-2021-3560 — 堆溢出, 结构体字段越界
 * 漏洞类型: 堆溢出 (结构体末尾数组越界)
 * 触发条件: malloc(sizeof(struct)+extra), 但写入超过extra
 * 根因: 分配sizeof(struct_a)+8, 写入sizeof(struct_a)+64
 * 有效原因: 测试结构推断+偏移溢出检测
 */
#include <stdlib.h>
#include <string.h>

struct buffer {
    int size;
    char data[8];  /* 末尾柔性数组模式 */
};

void struct_overflow(char *input, int inputlen) {
    /* 分配: sizeof(int)=4 + data[8] = 12, 但只malloc 12 */
    struct buffer *buf = (struct buffer *)malloc(sizeof(struct buffer));
    if (!buf) return;
    buf->size = inputlen;
    /* 写入inputlen字节到data: 若inputlen>8则溢出 */
    if (inputlen > 0) {
        memcpy(buf->data, input, inputlen);
    }
    free(buf);
}

int main() {
    char data[64] = "AAAA";
    struct_overflow(data, 32);   /* 32 > 8: 溢出24字节 */
    return 0;
}
