/*
 * UAF 安全对照 B — 引用计数正确管理 (TN)
 * 目标: 验证 refcnt 保护的释放不误报
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct object {
    int refcnt;
    char name[8];
};

struct object *obj_get(struct object *o) {
    o->refcnt++;
    return o;
}

void obj_put(struct object *o) {
    if (--o->refcnt == 0)
        free(o);              /* 仅最后一个引用释放 */
}

int main(int argc, char **argv) {
    struct object *o = (struct object *)malloc(sizeof(*o));
    o->refcnt = 1;
    strcpy(o->name, "obj0");

    struct object *r1 = obj_get(o);   /* refcnt=2 */
    struct object *r2 = obj_get(o);   /* refcnt=3 */
    obj_put(r1);                      /* 2 */
    obj_put(r2);                      /* 1 */
    /* o 仍有效 */
    printf("%s\n", o->name);
    obj_put(o);                       /* 0 → 释放, 之后不再使用 */
    return 0;
}
