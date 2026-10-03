/*
 * CVE-2016-6187 模式复刻 — apparmor exec UAF (内核)
 * 真实漏洞: apparmor exec 路径 release 后使用, 可本地提权
 * 触发条件: execve 与 profile 更新竞争
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct aa_profile {
    char name[16];
    int refcnt;
    int flags;
};

struct aa_task {
    struct aa_profile *profile;
    int exec_completed;
};

void aa_profile_free(struct aa_profile *p) {
    free(p);
}

int aa_exec_update(struct aa_task *t) {
    /* 缺陷: exec 完成后 profile 引用未管理 */
    aa_profile_free(t->profile);
    t->exec_completed = 1;
    return 0;
}

int aa_get_profile_flags(struct aa_task *t) {
    /* 缺陷: 未检查 profile 有效性 */
    return t->profile->flags;   /* UAF 读 */
}

int main(int argc, char **argv) {
    struct aa_task *t = (struct aa_task *)malloc(sizeof(*t));
    t->profile = (struct aa_profile *)malloc(sizeof(*t->profile));
    t->profile->flags = 0x2;
    strcpy(t->profile->name, "apparmor");
    t->exec_completed = 0;

    aa_exec_update(t);
    printf("flags: %d\n", aa_get_profile_flags(t));   /* UAF */
    free(t);
    return 0;
}
