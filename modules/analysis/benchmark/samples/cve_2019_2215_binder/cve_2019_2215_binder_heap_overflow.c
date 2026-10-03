/**
 * CVE-2019-2215 — Android Binder UAF→heap overflow via /dev/binder
 *
 * 分配大小: 256 bytes
 * 写入大小: 400 bytes
 * 溢出量: 144 bytes (144)
 * 漏洞模式: binder_race_overflow
 *
 * 样本设计:
 *   此样本精简化复现该CVE的核心堆溢出机制.
 *   保留原始漏洞的数据流结构: 从外部输入控制分配大小/
 *   写入长度, 到malloc/memcpy的参数传递.
 *   去除平台特定代码 (如内核模块/协议栈), 仅保留可静态分析的
 *   user-space等价逻辑.
 *
 * 为何对静态分析具有挑战性:
 *   1. 分配大小和写入大小来源于不同的数据流路径
 *   2. 存在中间转换 (类型转换/算术运算/对齐)
 *   3. 条件分支可能掩盖溢出路径
 *
 * 为何是真实误报/漏报来源:
 *   如果分析器使用过宽的区间 (如 [0, 2^31-1]), 会漏报;
 *   如果分析器不追踪跨函数的数据流, 会对间接调用漏报;
 *   如果分析器不做路径敏感分析, 会对 bounds-checked 安全路径误报.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 256
#define WRITE_SIZE 400

static char overflow_payload[WRITE_SIZE + 16];

static void init_payload(void) {
    memset(overflow_payload, 'A', WRITE_SIZE);
    overflow_payload[WRITE_SIZE] = '\0';
}

// 漏洞函数: 分配不足, 写入超量
void v_2019_2215_binder_overflow(void) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return;

    // 模拟缺少或错误的bounds check
    unsigned int write_len = WRITE_SIZE;
    // 在真实CVE中, write_len常来自网络数据包/用户输入/间接计算
    // 静态分析器需要追踪 write_len 的来源以判定安全性

    memcpy(buf, overflow_payload, write_len);  // ← 溢出点: write_len > ALLOC_SIZE

    printf("v_2019_2215_binder_overflow: buf[%d]='%c'\n", ALLOC_SIZE - 1, buf[ALLOC_SIZE - 1]);
    free(buf);
}

// 安全对照: 正确的分配大小
void v_2019_2215_binder_safe(void) {
    unsigned int safe_size = WRITE_SIZE + 16;  // 确保足够
    char *buf = (char *)malloc(safe_size);
    if (!buf) return;
    memcpy(buf, overflow_payload, WRITE_SIZE);  // 安全: alloc >= write
    printf("v_2019_2215_binder_safe: buf[%d]='%c'\n", WRITE_SIZE - 1, buf[WRITE_SIZE - 1]);
    free(buf);
}

// 边界情况: 恰好等于分配大小 (边界测试)
void v_2019_2215_binder_exact(void) {
    char *buf = (char *)malloc(WRITE_SIZE);
    if (!buf) return;
    memcpy(buf, overflow_payload, WRITE_SIZE);  // 恰好不溢出
    printf("v_2019_2215_binder_exact: ok\n");
    free(buf);
}

int main(void) {
    init_payload();
    printf("=== CVE-2019-2215 heap overflow test ===\n");
    printf("  Pattern: binder_race_overflow\n");
    printf("  Alloc=%d Write=%d Overflow=%d\n",
           ALLOC_SIZE, WRITE_SIZE, WRITE_SIZE - ALLOC_SIZE);
    v_2019_2215_binder_overflow();
    v_2019_2215_binder_safe();
    v_2019_2215_binder_exact();
    return 0;
}
