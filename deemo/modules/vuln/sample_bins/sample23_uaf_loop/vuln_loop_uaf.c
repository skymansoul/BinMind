/* sample23: 循环UAF — 循环中释放后残留指针仍在后续迭代中使用

 * 漏洞类型: Loop-based UAF
 * CVE映射: CVE-2023-5178 (NVMe-of loop UAF in Linux kernel)
 * 触发条件: for循环中每次迭代分配→使用→释放, 但某次迭代的指针被存储后
 *           在释放后仍通过存储的引用访问
 * 测试价值: 循环内分配模式的追踪 — 多条分配/释放交织
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct node {
    int id;
    char *payload;
    struct node *next;
} Node;

int main(void) {
    Node *head = NULL;
    Node *dangling = NULL;

    /* 构建链表 */
    for (int i = 0; i < 3; i++) {
        Node *n = (Node *)malloc(sizeof(Node));
        n->id = i;
        n->payload = (char *)malloc(32);
        snprintf(n->payload, 32, "node_%d_data", i);
        n->next = head;
        head = n;
        if (i == 1) dangling = n;  /* 保存指针 */
    }

    /* 释放所有节点 */
    Node *cur = head;
    while (cur) {
        Node *tmp = cur->next;
        free(cur->payload);
        free(cur);
        cur = tmp;
    }

    /* [VULN] 循环UAF: dangling 指向 node[1], 其 payload 和自身均已释放 */
    if (dangling) {
        printf("Dangling node %d: %s\n", dangling->id, dangling->payload);
    }

    return 0;
}
