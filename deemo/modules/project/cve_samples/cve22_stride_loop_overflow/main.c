// cve22_stride_loop_overflow — 跨步区间溢出检测
// CVE参考: STRIDE-OVERFLOW, 模式: strided_loop_overflow
// 关键: for(i=0;i<80;i+=4) — 20个写入点, i=76时偏移76>63, 越界
// 标准区间: 写入[0,79], 分配[0,63] → DEFINITE_OVERFLOW
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 64
#define LOOP_BOUND 80

int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 步长4循环: 访问偏移{0,4,8,...,76}
    // 最大偏移76 > 63, 溢出!
    for (int i = 0; i < LOOP_BOUND; i += 4) {
        buf[i] = (unsigned char)(i & 0xFF);
    }

    printf("buf=%p, stride-4 overflow at i=76, alloc=%d\n",
           (void *)buf, ALLOC_SIZE);
    free(buf);
    return 0;
}
