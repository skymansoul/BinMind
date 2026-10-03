/* 条件性堆溢出 (通过分支条件保护的安全代码 — 用于测试路径窄化)
 *
 * 场景: size 来自用户输入, 但被条件约束: if (size > MAX) size = MAX;
 * 后续的堆操作在 MAX 范围内是安全的。
 *
 * 测试目标: 路径窄化应证明当执行到 heap_access 时,
 * size 已被条件约束到安全范围。这测试 Phase 2 (Path Narrowing)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 256

static void safe_after_check(int size, const char *data) {
    char *buf;

    /* 安全约束: size 被缩窄到 [0, MAX_SIZE] */
    if (size > MAX_SIZE)
        size = MAX_SIZE;

    buf = (char *)malloc(MAX_SIZE);
    if (!buf) return;

    /* SAFE: size ≤ MAX_SIZE 在路径上成立 */
    memcpy(buf, data, size);
    printf("buf: %.256s\n", buf);
    free(buf);
}

static void unsafe_no_check(int size, const char *data) {
    char *buf;

    /* 无约束分支: size 仍为用户输入值 */
    buf = (char *)malloc(MAX_SIZE);
    if (!buf) return;

    /* UNSAFE: size 可能 > MAX_SIZE */
    memcpy(buf, data, size);
    printf("buf: %.256s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    char data[1024];
    int size;
    memset(data, 'X', sizeof(data));
    size = (argc >= 2) ? atoi(argv[1]) : 100;

    safe_after_check(size, data);   /* 预期: 安全, 过滤 */
    unsafe_no_check(size, data);    /* 预期: 保留告警 */
    return 0;
}
