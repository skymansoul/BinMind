/* 样本09: calloc分配后的溢出
 * 模式: calloc(nmemb, size)后, 错误计算总大小导致溢出
 * CVE参考: CVE-2020-10713 (Grub2: calloc整数溢出)
 * 触发条件: nmemb*size的乘积与后续使用的大小不匹配
 * 为何有效: 测试检测器对calloc(nmemb,size)的建模
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int count = argc > 1 ? atoi(argv[1]) : 4;
    int elem_size = 32;
    /* calloc(4, 32) = 128B */
    char *buf = (char *)calloc(count, elem_size);
    if (!buf) return 1;

    /* 漏洞: 每个元素应32B, 但实际写入64B到第一个元素 */
    int fake_elem_size = 64;
    memset(buf, 'C', fake_elem_size * count);
    printf("calloc(%d,%d)=%dB but wrote %dB\n",
           count, elem_size, count * elem_size, fake_elem_size * count);
    free(buf);
    return 0;
}
