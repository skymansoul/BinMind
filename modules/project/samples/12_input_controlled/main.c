/* 样本12: 输入控制的malloc大小 + 溢出
 * 模式: malloc(input_size) where input_size可被攻击者控制,
 *   然后写入固定大值. 攻击者可先调小input_size让分配变小从而溢出
 * CVE参考: CVE-2017-5638 (Struts2, 类似模式)
 * 触发条件: input_size很小(如16), 但写入256B
 * 为何有效: 测试污点传播+分配大小输入可控的联合检测
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    /* 攻击者可通过参数控制分配大小 */
    int alloc_sz = argc > 1 ? atoi(argv[1]) : 16;
    if (alloc_sz <= 0) alloc_sz = 1;

    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return 1;

    /* 固定大写入 — 若alloc_sz调小即溢出 */
    memset(buf, 'X', 256);

    printf("malloc(%d) + write 256B\n", alloc_sz);
    free(buf);
    return 0;
}
