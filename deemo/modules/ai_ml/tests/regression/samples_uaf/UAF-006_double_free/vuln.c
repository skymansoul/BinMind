/* UAF-006: 双重释放——同一指针被free两次，第二次free时ptr已被释放
 * 场景: free(ptr) → ... → free(ptr) — 第二次free时ptr已是悬垂指针
 * 别名追踪器能力: 记录每个别名集合的free历史→检测重复free
 * 预期: 检测到double-free(与UAF同等的危险模式)
 */

#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int refcount;
    void *payload;
} RefObj;

RefObj *create_refobj(size_t payload_size) {
    RefObj *obj = (RefObj *)malloc(sizeof(RefObj));
    if (!obj) return NULL;

    obj->payload = malloc(payload_size);
    if (!obj->payload) {
        free(obj);
        return NULL;
    }
    obj->refcount = 1;
    return obj;
}

void refobj_retain(RefObj *obj) {
    if (obj) obj->refcount++;
}

void refobj_release(RefObj *obj) {
    if (!obj) return;

    obj->refcount--;
    if (obj->refcount <= 0) {
        free(obj->payload);
        free(obj);
        /* BUG: 缺少 obj = NULL; */
    }
}

void unsafe_cleanup(RefObj *obj) {
    /* BUG: 无视refcount直接double-free
     * 调用者可能已调用过refobj_release */
    free(obj->payload);  /* 可能已释放 */
    free(obj);           /* 可能已释放 */
}

int main(void) {
    RefObj *r = create_refobj(256);
    refobj_retain(r);  /* refcount=2 */

    refobj_release(r); /* refcount=1 → 不释放 */
    refobj_release(r); /* refcount=0 → 释放 */

    /* BUG: 再次释放——double free */
    unsafe_cleanup(r);  /* r已被释放，再次free→double-free */

    return 0;
}
