/*
 * CVE-06: 用户可控分配大小
 *
 * 模式: size 来自 argv/输入, 无上限检查, 后续写入依赖该 size
 * 触发: atoi(argv[1]) → malloc(size) → memcpy with attacker-controlled data
 *
 * 对应真实 CVE: CVE-2020-10713 (GRUB2 BootHole 堆溢出变体)
 * 检测预期: 分配大小来自用户输入, 应标记为 tainted — 需运行时判断
 *   FP 过滤不应滤除 (用户输入 + 无约束 → 真阳性)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: %s <alloc_size> <write_size>\n", argv[0]);
        return 0;
    }

    int alloc_sz = atoi(argv[1]);
    int write_sz = atoi(argv[2]);

    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return 1;

    // 无上限检查 — 若 write_sz > alloc_sz, 溢出
    memset(buf, 'B', write_sz);

    printf("alloc=%d write=%d\n", alloc_sz, write_sz);
    free(buf);
    return 0;
}
