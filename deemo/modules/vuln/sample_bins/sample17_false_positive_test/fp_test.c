/* sample17: 误报测试 — 编译器padding + 对齐 + 分配器舍入组合场景
 *
 * 漏洞类型: 无 — 这些访问在二进制层面是合法的
 * 触发条件: 源码层面的"越界"访问实际上被分配器的尺寸舍入覆盖
 * 测试价值: 核心FP测试用例 — 验证分配器感知的误报过滤器是否有效
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int header;
    int type;
    char data[100];  // 名义上100字节
} Message;

void process_message(int msg_type, const char *input) {
    // malloc(100) → ptmalloc2实际分配 112+header → usable ≈ 104
    // 源码中 data[100] 占 100 字节
    // 但编译器可能访问 data[103] 作为结构体尾部padding访问
    Message *msg = (Message *)malloc(sizeof(Message));
    if (!msg) return;
    msg->header = 0xDEADBEEF;
    msg->type = msg_type;
    memcpy(msg->data, input, 100);

    // [FP-RISK] 编译器可能生成: *(msg+108) = 0 作为4字节对齐填充
    // 这在二进制层面合法 (usable=104, 但加上header/type后刚好),
    // 但简单的源码级分析会误报为"越界写入"
    msg->data[99] = '\0';  // 安全
    printf("msg: %s\n", msg->data);
    free(msg);
}

void allocator_padding_scenario(void) {
    // ptmalloc2 MINSIZE=32, malloc(1) → usable=16
    char *tiny = (char *)malloc(1);
    // 编译器可能在这里生成 *(tiny+15)=0, 这在使用 ptmalloc2 时合法
    memset(tiny, 0, 16);  // 在二进制层完全合法
    printf("tiny allocated\n");
    free(tiny);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <msg>\n", argv[0]); return 1; }
    process_message(1, argv[1]);
    allocator_padding_scenario();
    return 0;
}
