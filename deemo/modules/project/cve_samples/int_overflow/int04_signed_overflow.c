// int04_signed_overflow: 有符号整数溢出 → 负值绕过边界检查
// 模式: signed int加法溢出 (C未定义行为)
// 预期检测: Mode 4 (SADD_OVF) — 有符号溢出
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int user_size = 0x7FFFFFF0;  // INT_MAX - 15
    if (argc > 1) user_size = atoi(argv[1]);

    // 漏洞: user_size + header_size 可能超过 INT_MAX,
    // 在有符号运算中回绕为负值
    int header_size = 32;
    int total = user_size + header_size;

    // 若total变成负值, 条件 total > 0 失败, 但后续用total分配
    // 实际上这不是最危险的 — 更危险的是 total变为负值后
    // 转成无符号用于malloc → 极大值
    if (total <= 0 || total > 0x100000) {
        printf("size out of range\n");
        return 1;
    }

    // 即使检查通过: user_size=0x7FFFFFF0, total=0x80000010 (有符号: -2147483632)
    // total > 0 → false → 被拒绝, 这条路径是安全的
    // 但若检查是 total > 0 && total < MAX: total为负时条件失败, 安全
    // 真正危险: if (total < MAX) { malloc(total) } — 负的total转无符号 = 极大值
    char *buf = (char *)malloc((unsigned int)total);
    if (!buf) return 1;

    memcpy(buf, "test", 4);
    free(buf);
    return 0;
}
