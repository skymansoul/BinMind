/*
 * FP_uaf_guarded_path — 条件路径保护 (False Positive for TARPS Stage D).
 *
 * 场景: if(p) { free(p); return; } 后续代码中 use(p)
 *       但实际上 free后立即return, 后续的use(p)在另一路径上.
 * TARPS Stage D (路径条件) 应识别 free路径不可达于use.
 *
 * 预期: 基线检测器可能误报 (看到 free→use),
 *       TARPS应通过路径条件分析正确过滤.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int refcount;
    char *buffer;
} ManagedObj;

void cleanup_object(ManagedObj *obj) {
    if (obj != NULL) {
        free(obj->buffer);
        free(obj);
        return;  /* free后立即返回 */
    }
    /* 以下代码仅当 obj==NULL 时可达 */
    printf("object already null\n");
}

int main() {
    ManagedObj *obj = (ManagedObj *)malloc(sizeof(ManagedObj));
    if (!obj) return 1;
    obj->refcount = 1;
    obj->buffer = (char *)malloc(32);
    strcpy(obj->buffer, "hello");

    /* obj != NULL, 所以cleanup中free后return,
       use(obj) 不可达 */
    cleanup_object(obj);

    return 0;
}
