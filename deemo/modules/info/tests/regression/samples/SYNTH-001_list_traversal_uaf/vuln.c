/* SYNTH-001: 链表遍历UAF — 经典样本
 * 模式: while (cur) { free(cur); cur = cur->next; }
 * 这是所有UAF检测器的结构性盲点:
 *   - 检测器追踪 free(cur) → use(cur), 不追踪 free(cur) → cur->next
 *   - cur->next 访问发生在 free 之后、cur 被重新赋值之前
 *   - 字段穿越访问是"二级UAF"的主要形式 (Undangle, NDSS 2011)
 *
 * 预期: detect_list_traversal_uaf 检出, confidence >= 0.88
 */

#include <stdlib.h>
#include <stdio.h>

typedef struct node {
    int data;
    struct node *next;
    struct node *prev;
} node_t;

/* 场景1: 经典链表释放后遍历 */
void cleanup_list(node_t *head) {
    node_t *cur = head;
    while (cur != NULL) {
        node_t *tmp = cur;
        free(cur);              /* ← free(cur) */
        cur = cur->next;        /* ← UAF! 访问已释放的 cur->next */
        printf("freed node: %p\n", tmp);
    }
}

/* 场景2: 树遍历UAF */
typedef struct tnode {
    int key;
    struct tnode *left;
    struct tnode *right;
} tnode_t;

void cleanup_tree(tnode_t *root) {
    if (root == NULL) return;
    cleanup_tree(root->left);
    cleanup_tree(root->right);
    free(root);                 /* free(node) */
    /* root->left 和 root->right 已释放但仍然被上层递归访问 — UAF */
}

/* 场景3: 通用字段穿越UAF */
typedef struct context {
    int id;
    char *name;
    void *data;
} ctx_t;

void process_and_free(ctx_t *ctx) {
    free(ctx);                  /* free(ctx) */
    if (ctx->id > 0) {         /* UAF: ctx->id 在free后访问 */
        printf("id: %d\n", ctx->id);  /* UAF: ctx->id 再次访问 */
    }
}

int main() {
    node_t *list = malloc(sizeof(node_t));
    list->data = 1;
    list->next = malloc(sizeof(node_t));
    list->next->data = 2;
    list->next->next = NULL;
    cleanup_list(list);
    return 0;
}
