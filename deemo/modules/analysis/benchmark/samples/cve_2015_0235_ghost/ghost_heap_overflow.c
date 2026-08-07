/**
 * CVE-2015-0235 (GHOST) 堆溢出精简复现
 *
 * 漏洞模式: realloc 后 size 不一致导致堆溢出.
 * 在原始 GHOST 中, gethostbyname 在处理超长主机名时,
 * realloc 返回更大的缓冲区, 但后续 memcpy 仍使用旧的 size,
 * 导致越界写入直到 '\0' 结束符.
 *
 * 本样本: malloc(128) → realloc(256) → memcpy 用旧size(384)=溢出128字节
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OLD_SIZE 128
#define NEW_SIZE 256
#define WRITE_SIZE 384  // > NEW_SIZE, 模拟 realloc 后大小不一致

static char payload[WRITE_SIZE + 1];

void init_payload(void) {
    memset(payload, 'A', WRITE_SIZE);
    payload[WRITE_SIZE] = '\0';
}

void ghost_realloc_overflow(void) {
    // 初始分配
    char *buf = (char *)malloc(OLD_SIZE);
    if (!buf) return;

    // realloc 扩大缓冲区
    char *new_buf = (char *)realloc(buf, NEW_SIZE);
    if (!new_buf) { free(buf); return; }

    // 漏洞: 使用 OLD_SIZE 的逻辑错误 → 实际写入 WRITE_SIZE,
    // 但 new_buf 只有 NEW_SIZE 字节可用
    // 在原始漏洞中, 这是通过 strcpy 触发的 (写入到 '\0' 为止)
    memcpy(new_buf, payload, WRITE_SIZE);  // ← 溢出 WRITE_SIZE - NEW_SIZE = 128 bytes

    printf("ghost_realloc: buf[%d]='%c'\n", NEW_SIZE - 1, new_buf[NEW_SIZE - 1]);
    free(new_buf);
}

// 安全对照: realloc 后正确使用新 size
void ghost_realloc_safe(void) {
    char *buf = (char *)malloc(OLD_SIZE);
    if (!buf) return;
    char *new_buf = (char *)realloc(buf, WRITE_SIZE);  // realloc 到足够大
    if (!new_buf) { free(buf); return; }
    memcpy(new_buf, payload, WRITE_SIZE);  // 安全: 分配大小 = 写入大小
    printf("ghost_safe: buf[%d]='%c'\n", WRITE_SIZE - 1, new_buf[WRITE_SIZE - 1]);
    free(new_buf);
}

int main(void) {
    init_payload();
    printf("=== CVE-2015-0235 GHOST heap overflow test ===\n");
    ghost_realloc_overflow();
    ghost_realloc_safe();
    return 0;
}
