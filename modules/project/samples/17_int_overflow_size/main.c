/* 样本17: 整数溢出导致的小分配+大写入
 * 模式: malloc(user_size * elem_size), user_size超大导致整数溢出回绕
 * CVE参考: CVE-2014-0160 (OpenSSL Heartbleed中的类似模式)
 * 触发条件: user_size * elem_size溢出为小值, malloc返回小buf, 写入大值
 * 为何有效: 测试检测器对malloc参数值域异常大的处理
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char **argv) {
    /* 攻击者控制的大小: 若为0x40000001, 乘以4后溢出为4 */
    uint32_t user_count = argc > 1 ? (uint32_t)atoi(argv[1]) : 1;
    uint32_t elem_size = 4;
    uint32_t alloc_size = user_count * elem_size; /* 可能溢出 */

    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;
    printf("malloc(%u * %u = %u) returned %p\n",
           user_count, elem_size, alloc_size, (void *)buf);

    /* 漏洞: 按原始user_count * elem_size写入, 而非实际分配大小 */
    memset(buf, 'I', user_count * elem_size);

    free(buf);
    return 0;
}
