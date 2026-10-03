/*
 * CVE-25: 嵌套循环溢出 — 外层循环×内层循环累积写入超过分配
 *
 * 模式: malloc(128), for(i<8) for(j<8) buf[i*16+j] = x → 64B写入, 安全
 * 改为: for(i<16) for(j<8) → 128B写入, usable(128)=136 → 安全(slack)
 * 再改: for(i<16) for(j<10) → 160B写入 > 136 → 溢出
 *
 * 对应: 类似 CVE-2018-16864 (systemd 堆溢出, 嵌套循环)
 * 检测预期: PROVEN_OVERFLOW (loop_bound=16*10=160 > 136 usable)
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;

    int i, j;
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 10; j++) {
            buf[i * 10 + j] = 'A';
        }
    }

    printf("nested_loop done\n");
    free(buf);
    return 0;
}
