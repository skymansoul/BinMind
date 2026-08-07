/* UAF-002: 条件释放——free在条件分支内，后续use可能无害
 * 场景: if(err) { free(ptr); return; } — free只在错误路径执行
 *       正常路径上 ptr 未被释放，后续use是安全的
 * uaf_state_machine缺陷: 无条件假设free必然执行→FP
 * 路径分析器能力: 识别cmp/jcc→条件分支→置信度降级
 * 预期: 原有状态机报告UAF(FP)，增强过滤器降级为UNCERTAIN
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_DATA 256

typedef struct {
    char *buffer;
    size_t length;
} Message;

Message *create_message(const char *input, size_t len) {
    Message *msg = (Message *)malloc(sizeof(Message));
    if (!msg) return NULL;

    msg->buffer = (char *)malloc(MAX_DATA);
    if (!msg->buffer) {
        /* 条件free: 仅当内部分配失败时释放外层 */
        free(msg);
        return NULL;
    }

    /* 正常路径: msg仍有效 */
    msg->length = (len < MAX_DATA) ? len : MAX_DATA;
    memcpy(msg->buffer, input, msg->length);
    msg->buffer[msg->length] = '\0';

    /* 安全使用——msg未被free */
    printf("message created: %s\n", msg->buffer);
    return msg;
}

void cleanup_message(Message *msg) {
    if (msg) {
        free(msg->buffer);
        free(msg);
    }
}

int main(void) {
    Message *m = create_message("hello uaf test", 13);
    cleanup_message(m);
    return 0;
}
