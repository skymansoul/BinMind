/*
 * FP_uaf_refcount_protected — 引用计数保护 (False Positive for TARPS Stage E).
 *
 * 场景: 引用计数减到0才free, free后不再有引用.
 * 模拟Linux内核 kref_put 模式.
 * TARPS Stage E (引用计数) 应识别 refcount_dec→free 保护.
 *
 * 预期: 基线检测器可能误报 (看到free后全局指针仍存在),
 *       TARPS应通过引用计数分析正确过滤.
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int refcount;
    int value;
    char name[32];
} RefObj;

static RefObj *g_obj = NULL;

void ref_get(RefObj *obj) {
    if (obj) obj->refcount++;
}

void ref_put(RefObj *obj) {
    if (!obj) return;
    obj->refcount--;
    if (obj->refcount <= 0) {
        /* 引用计数归零, 安全释放 */
        free(obj);
        if (obj == g_obj) {
            g_obj = NULL;  /* 清除全局引用 */
        }
        return;
    }
}

int main() {
    RefObj *obj = (RefObj *)malloc(sizeof(RefObj));
    if (!obj) return 1;
    obj->refcount = 1;  /* 初始引用 */
    obj->value = 99;

    g_obj = obj;
    ref_get(obj);  /* refcount=2 */

    /* 正常使用 */
    printf("value=%d\n", obj->value);

    ref_put(obj);  /* refcount=1 → 不释放 */
    ref_put(obj);  /* refcount=0 → 释放 + g_obj=NULL */

    /* g_obj已置NULL, 安全 */
    if (g_obj != NULL) {
        printf("value=%d\n", g_obj->value);  /* 不可达 */
    }

    return 0;
}
