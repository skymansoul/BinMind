/*
 * UAF-STRUCT-FIELD — 释放后经结构体字段访问
 * free(obj) 后经 obj->field 写入/读取.
 * 触发: delete_node() 释放节点后访问其字段.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Node {
    int id;
    char *name;
} Node;

Node *node = NULL;

void delete_node(void) {
    free(node->name);
    free(node);
    /* 漏洞: 释放后访问字段 */
    node->id = 0;
}

int main(void) {
    node = (Node *)malloc(sizeof(Node));
    if (!node) return 1;
    node->name = (char *)malloc(16);
    if (!node->name) return 1;
    strcpy(node->name, "x");
    node->id = 7;
    delete_node();
    return 0;
}
