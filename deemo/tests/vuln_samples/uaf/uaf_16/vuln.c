/* CVE-2025-uaf-objcache CWE-416: 全局对象缓存 — 对象free后未从链表移除, 后续查找返回悬垂指针 */
#include <stdlib.h>
#include <string.h>

typedef struct Obj {
    int id;
    char data[64];
    struct Obj *next;
} Obj;

static Obj *g_cache = NULL;

/* 将对象加入全局缓存链表 */
void cache_add(Obj *o) {
    o->next = g_cache;
    g_cache = o;
}

/* 从缓存中查找对象 (不检查是否已free) */
Obj *cache_find(int id) {
    Obj *cur = g_cache;
    while (cur) {
        if (cur->id == id) return cur;
        cur = cur->next;
    }
    return NULL;
}

/* BUG: 释放对象但未从缓存链表中移除 */
void obj_destroy(Obj *o) {
    free(o);
    /* 缺少: 从g_cache中移除o */
}

/* 攻击路径: free后通过缓存查找获取悬垂指针并写入 */
int trigger_uaf(int target_id) {
    Obj *a = malloc(sizeof(Obj));
    a->id = 100;
    a->next = NULL;
    cache_add(a);

    Obj *b = malloc(sizeof(Obj));
    b->id = target_id;
    b->next = NULL;
    cache_add(b);

    /* 释放b但b仍在g_cache链表中 */
    obj_destroy(b);

    /* 通过缓存查找b — 返回悬垂指针 */
    Obj *found = cache_find(target_id);
    if (found) {
        /* UAF: 写入已释放的对象 */
        memset(found->data, 'A', 64);
        return 1;
    }
    return 0;
}

int main() {
    trigger_uaf(42);
    return 0;
}
