/*
 * 跨函数格式字符串漏洞样本 — 包装函数返回/构造格式字符串。
 *
 * 模式1: get_fmt(n) 条件返回 "%s" 或 "%n"
 * 模式2: build_fmt(buf, n) 内部 sprintf 构造 "%%...%n"
 *
 * 与 fmt_detector 互补: 现有检测器通过全局 %n 扫描和变量追踪,
 * 本样本测试跨函数返回的格式字符串检测。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── 模式1: 条件返回格式字符串字面量 ── */

/* 危险: 当 n=0 时返回 "%n" — 可被用户控制路径触发 */
const char *get_fmt(int n) {
    if (n > 0) {
        return "%s\n";
    } else {
        return "%n";   /* ← 格式字符串写原语! */
    }
}

/* 安全对比: 始终返回安全格式串 */
const char *get_safe_fmt(const char *data) {
    (void)data;
    return "data: %s\n";  /* 固定格式串, 无 %n */
}

/* ── 模式2: 动态构造格式字符串 ── */

/* 危险: sprintf(buf, "%%%d$n", n) 构造 %n 格式串 */
char *build_fmt(char *buf, int n) {
    sprintf(buf, "%%%d$n", n);  /* 如果 n 来自用户输入, 构造任意 %n */
    return buf;
}

/* 危险: sprintf(buf, "%%%ds", width) 构造宽度 */
char *build_width_fmt(char *buf, int width) {
    sprintf(buf, "%%%ds", width);
    return buf;
}

int main(int argc, char *argv[]) {
    int user_val = argc > 1 ? atoi(argv[1]) : 0;

    /* ── 跨函数格式串 (模式1) ── */
    /* BUG: get_fmt(user_val) 可能返回 "%n" */
    printf(get_fmt(user_val), "hello");        /* line 56 — fmt_cross_func#1 */

    /* 安全: get_safe_fmt 始终返回固定格式串 */
    printf(get_safe_fmt("world"), "hello");    /* line 59 — 安全 */

    /* ── 跨函数格式串 (模式2) ── */
    char buf[64];
    /* BUG: build_fmt 动态构造 %n 格式串 */
    printf(build_fmt(buf, user_val), &user_val);  /* line 63 — fmt_cross_func#2 */

    /* BUG: build_width_fmt 构造宽度 (非 %n, 但用户控制宽度) */
    printf(build_width_fmt(buf, user_val), "data"); /* line 66 — fmt_cross_func#3 */

    /* ── 间接使用 ── */
    /* BUG: 通过中间变量使用包装函数返回的格式串 */
    const char *fmt = get_fmt(user_val);
    printf(fmt, "world");                     /* line 70 — fmt_cross_func#4 */

    return 0;
}
