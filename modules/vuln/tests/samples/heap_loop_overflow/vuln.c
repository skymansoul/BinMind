/* 循环中堆溢出 (通用模式 — 嵌套循环导致累加超出分配)
 *
 * 触发条件: 外层循环中每次迭代向堆缓冲追加数据,
 * 假设总大小不超过分配值, 但实际迭代次数可能超出预期。
 *
 * 测试目标: 循环内的值域累积分析 — 需要证明每次迭代
 * 的 offset 累加不超过分配大小。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int append_items(char **items, int n_items, int item_size) {
    char *buf;
    int i, total = 0;

    /* 假设每项 item_size 字节 */
    buf = (char *)malloc(n_items * item_size);
    if (!buf) return -1;

    /* BUG: 写入 n_items+1 个项, 多了一个 */
    for (i = 0; i <= n_items; i++) {
        memcpy(buf + total, "ITEM", 4);
        total += item_size;
    }

    *items = buf;
    return total;
}

int main(int argc, char **argv) {
    char *items;
    int n;
    n = (argc >= 2) ? atoi(argv[1]) : 10;
    append_items(&items, n, 16);
    free(items);
    return 0;
}
