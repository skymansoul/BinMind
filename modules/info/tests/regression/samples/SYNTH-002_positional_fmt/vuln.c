/* SYNTH-002: 格式字符串深度检测 — 位置参数+变参计数+动态宽度
 * 覆盖 format_string_deep 的三个维度:
 *   维度1: 位置参数越界 (%7$p 引用不存在的第7个参数)
 *   维度2: 变参数量不匹配 (3个%说明符, 只给2个参数)
 *   维度3: 动态宽度字段 (%*s 宽度由参数栈控制)
 *
 * 预期: detect_format_string_deep 检出 ≥3 个发现
 */

#include <stdio.h>
#include <stdlib.h>

/* 维度1: 位置参数越界 — %7$p 但只有2个变参 */
void pos_param_leak(const char *user_fmt) {
    int a = 0x41, b = 0x42;
    /* 攻击者传入 "%7$p" → 读取栈上第7个参数位置 → 信息泄露 */
    printf(user_fmt, a, b);
}

/* 维度1变体: 位置参数直接写在代码中 */
void pos_param_hardcoded() {
    int x = 1, y = 2;
    /* %5$x 引用了第5个参数, 但实际只提供了2个 → OOB */
    printf("%d %5$x\n", x, y);
}

/* 维度2: 变参计数不足 — 3个格式符, 2个参数 */
void vararg_undercount() {
    /* printf("%s %d %x", a, b) — 3个说明符, 2个参数 */
    printf("%s %d %x\n", "test", 42);
}

/* 维度2变体: 参数过剩 — 多余参数被忽略 (低严重度) */
void vararg_overcount() {
    printf("%s\n", "a", "b", "c");  /* 1个%说明符, 3个参数 */
}

/* 维度3: 动态宽度 — %*s 从参数栈读取宽度 */
void dynamic_width_vuln(const char *user_input) {
    int width = 1024;  /* 攻击者可能控制此值 */
    /* %*s: width从栈上读取, 若width>目标缓冲区→溢出 */
    printf("%*s\n", width, user_input);
}

/* 维度3变体: sprintf 场景 — 更危险 */
void dynamic_width_sprintf(const char *input) {
    char buf[64];
    int pad = 256;  /* 攻击者控制 */
    /* 如果pad=256, 写入256字节到64字节buf → 栈溢出 */
    sprintf(buf, "%*s", pad, input);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        pos_param_leak(argv[1]);
    }
    pos_param_hardcoded();
    vararg_undercount();
    vararg_overcount();
    dynamic_width_vuln(argc > 1 ? argv[1] : "safe");
    dynamic_width_sprintf(argc > 1 ? argv[1] : "safe");
    return 0;
}
