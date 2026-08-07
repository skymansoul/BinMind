/* sample18: 基础UAF — malloc→free→use (最简模式)

 * 漏洞类型: Use-After-Free
 * CVE映射: 通用UAF模式, 见 CVE-2024-0223, CVE-2023-5217 等
 * 触发条件: free(p) 后未将 p 置 NULL, 后续代码路径继续使用 p
 * 测试价值: 验证 DT-HSA 对最基础 UAF 模式的检出能力 (应 confirmed)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char data[64];
} Item;

void process_item(void) {
    Item *it = (Item *)malloc(sizeof(Item));
    if (!it) return;
    it->id = 42;
    memset(it->data, 'A', 63);
    it->data[63] = '\0';

    printf("Item %d: %s\n", it->id, it->data);

    free(it);
    /* [VULN] UAF: free后继续使用 it->id */
    printf("Freed item id = %d\n", it->id);
}

int main(void) {
    process_item();
    return 0;
}
