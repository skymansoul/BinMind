// cve21_stride_loop_safe — 跨步区间安全验证
// CVE参考: STRIDE-SAFE, 模式: strided_loop_safe
// 关键: for(i=0;i<120;i+=8) — 步长8, 只有15个写入点
// 旧方法: 标准区间[0,119], 宽120 → 与分配120重叠, 可能溢出
// 新方法: 跨步区间[0,112,8], 所有访问点在{0,8,...,112}内, 确定安全
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 120

int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 步长8循环: 只访问偏移{0,8,16,...,112}
    // 最大偏移112 < 120, 完全安全
    for (int i = 0; i < ALLOC_SIZE; i += 8) {
        buf[i] = (unsigned char)(i & 0xFF);
    }

    printf("buf=%p, stride-8 loop < %d, SAFE\n",
           (void *)buf, ALLOC_SIZE);
    free(buf);
    return 0;
}
