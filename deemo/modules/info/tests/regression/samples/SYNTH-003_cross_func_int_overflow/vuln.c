/* SYNTH-003: 跨函数整数溢出 — 常量传播+位移+间接乘法
 * 覆盖 int_overflow_v3 + int_overflow_cross_func 的所有检测维度:
 *   L0: malloc(a*b) 结构风险
 *   L4: 1<<31 位移溢出
 *   L5: 类型截断
 *   跨函数: init(256) → callee中 N*4 已知常量
 *
 * 预期: detect_int_overflow_v3 检出 ≥2, detect_int_overflow_cross_func 检出 ≥1
 */

#include <stdlib.h>
#include <stdint.h>

/* 场景1: L0 结构风险 — malloc(a*b) 即使a,b范围未知 */
void process_data(int nitems, size_t item_size) {
    /* malloc(nitems * item_size) — 乘法分配, 即使范围未知也是风险 */
    void *buf = malloc(nitems * item_size);
    if (buf) {
        /* ... */
        free(buf);
    }
}

/* 场景2: L4 位移溢出 — 1<<31 对int32是未定义行为 */
int create_bitmask(int flag) {
    if (flag > 31) return -1;
    /* 1<<31 = 2147483648 > INT32_MAX → 符号位溢出 */
    int mask = 1 << flag;
    return mask;
}

/* 场景2b: 安全位移 — 1ULL<<40 显式64位, 不应报告 */
uint64_t create_large_mask() {
    return 1ULL << 40;  /* 安全: 明确使用64位 */
}

/* 场景3: L5 类型截断 */
void copy_data(size_t big_len) {
    /* (uint16_t)big_len — 截断到16位, 可能丢失高位 */
    uint16_t small_len = (uint16_t)big_len;
    char *buf = malloc(small_len);
    if (buf) free(buf);
}

/* 场景4: 跨函数常量传播 */
void init_buffer(int N) {
    /* N 在调用方是常量256, 但callee内部N范围是TOP */
    char *buf = malloc(N * 4);  /* 256*4=1024, 安全 */
    if (buf) {
        for (int i = 0; i < N; i++) {
            buf[i * 4] = 0;
        }
        free(buf);
    }
}

void init_buffer_from_call() {
    /* 调用方传入常量256 — 跨函数分析应能传播此常量 */
    init_buffer(256);
}

/* 场景4b: 跨函数大常量 — N=65536 → N*4=262144 超过uint16_t但安全 */
void init_large() {
    init_buffer(65536);  /* 65536*4=262144, 在int32内仍安全 */
}

/* 场景5: 间接乘法传播 */
void indirect_mult(int w, int h) {
    int sz = w * h;
    char *pixels = malloc(sz);  /* sz 来自 w*h */
    if (pixels) free(pixels);
}

int main() {
    process_data(1000, 8);
    create_bitmask(31);
    create_bitmask(20);
    create_large_mask();
    copy_data(70000);
    init_buffer_from_call();
    init_large();
    indirect_mult(1920, 1080);
    return 0;
}
