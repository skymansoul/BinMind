/* 无界拷贝堆溢出 (通用模式 — 类似 Heartbleed)
 *
 * 触发条件: 从用户输入读取长度字段, 无验证地用该长度做堆拷贝。
 * 攻击者说 "长度=65535" → 读65535字节到malloc(100)的缓冲区。
 *
 * 测试目标: 污点引擎应追踪 len 字段从输入到 memcpy 的完整路径,
 * 且检测到 len 未经边界验证。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct message {
    uint16_t len;      /* 用户可控 */
    char data[1024];   /* 实际数据 */
};

static int process_msg(const struct message *msg) {
    char *buf;
    /* 只分配了 256, 但 msg->len 可能是 1024 */
    buf = (char *)malloc(256);
    if (!buf) return -1;

    /* BUG: msg->len 未经验证, 可能 > 256 */
    memcpy(buf, msg->data, msg->len);
    buf[msg->len > 255 ? 255 : msg->len] = '\0';

    printf("msg: %s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    struct message msg;
    msg.len = 512;  /* 攻击者设置 > 256 */
    memset(msg.data, 'B', sizeof(msg.data));
    process_msg(&msg);
    return 0;
}
