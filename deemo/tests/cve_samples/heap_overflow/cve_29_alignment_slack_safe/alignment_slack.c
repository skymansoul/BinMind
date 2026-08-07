/*
 * CVE-29: 分配器对齐余量安全 — 写入超过malloc参数但在对齐边界内
 *
 * 模式: malloc(48), offset=52, write 8B → write_end=60
 * 安全: usable(48)=56 (glibc: 48+8=56→align_up(56,16)=56→usable=56-8=48?
 *       不, request2size(48): 48+8=56, align_up(56,16)=64, usable=64-8=56)
 *       write_end=60 > 56 → 溢出!
 * 修正: malloc(48), offset=44, write 8B → write_end=52 <= 56 → SAFE
 *
 * 对应: 类似 CVE-2022-3602 (OpenSSL punycode 堆溢出, 对齐边界)
 * 检测预期: PROVEN_SAFE (对齐后usable=56 >= 52)
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buf = (char *)malloc(48);
    if (!buf) return 1;

    /* offset 44 + 8B = 52 <= usable(48)=56 → within slack */
    *(long *)(buf + 44) = 0x4545454545454545L;

    printf("alignment_slack_safe done\n");
    free(buf);
    return 0;
}
