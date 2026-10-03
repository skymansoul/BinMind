/* UAF-004: 真实UAF——无条件free+跨基本块use
 * 场景: 多分支结构，任一分支free后另一分支仍可use→确定UAF
 * 增强过滤器能力: 三阶段全部通过→CONFIRMED 0.9置信度
 * 预期: L1别名追踪通过+L2无条件free通过+L3严重use通过→CONFIRMED
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct node {
    int key;
    char *value;
    struct node *next;
} Node;

Node *global_cache = NULL;

Node *find_or_create_node(int key) {
    /* 先查全局缓存 */
    if (global_cache && global_cache->key == key)
        return global_cache;

    Node *n = (Node *)malloc(sizeof(Node));
    if (!n) return NULL;

    n->key = key;
    n->value = (char *)malloc(128);
    if (!n->value) {
        free(n);
        return NULL;
    }
    n->next = NULL;
    return n;
}

void delete_node(Node *n) {
    if (!n) return;

    /* 从全局缓存移除 */
    if (global_cache == n)
        global_cache = n->next;

    /* UAF漏洞: 无条件free value */
    free(n->value);

    /* BUG: free value后仍在某些路径上使用 */
    if (n->next) {
        /* 此路径上value已被free——UAF */
        printf("next node key: %d, current value ptr: %p\n",
               n->next->key, (void *)n->value);
    }

    /* 条件分支内也可能use */
    if (n->key > 0) {
        /* 另一个路径也use freed指针 */
        size_t len = strlen(n->value);  /* UAF: deref freed ptr */
        printf("old value len: %zu\n", len);
    }

    free(n);
}

int main(void) {
    Node *a = find_or_create_node(10);
    if (a) {
        strcpy(a->value, "test_data_for_uaf_004");
    }
    Node *b = find_or_create_node(20);
    if (b) {
        a->next = b;
        strcpy(b->value, "second_node_data");
    }

    global_cache = a;
    delete_node(a);

    return 0;
}
