/*
 * sample_fmt_13 — 位置参数 %n 写入 (CWE-134 高级变体)
 * 模式: argv[1] → printf(argv[1])  — 位置参数可控 %n 写入
 * 利用: %2$n 向第二个参数指向的地址写入已输出字节数
 * 期望: CONFIRMED (置信度 ≥ 0.70)
 *
 * 与 fmt_01 的区别: 本样本专门测试位置参数 %n$ 语法,
 * 这是 format spec scorer 应特别加权的高危模式.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 危险: 用户输入直接作为 printf 格式字符串
// 攻击者可注入 %n / %hn / %hhn 实现任意地址写
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <format>\n", argv[0]);
        return 1;
    }

    // 故意暴露局部变量地址 (模拟真实场景中攻击者可通过泄漏获取)
    int target = 0x41414141;
    printf("target @ %p, value = 0x%x\n", (void *)&target, target);

    // CWE-134: printf(argv[1]) — 格式字符串在攻击者控制下
    // 高危模式: %n, %hn, %hhn, %2$n (位置参数 + 写入)
    printf(argv[1]);

    printf("\ntarget after = 0x%x\n", target);
    if (target != 0x41414141) {
        printf("[!] target modified via %%n — exploit confirmed\n");
    }
    return 0;
}
