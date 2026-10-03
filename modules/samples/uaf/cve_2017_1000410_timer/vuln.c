/*
 * CVE-2017-1000410 模式复刻 — 内核 UAF (ALSA timer)
 * 真实漏洞: snd_timer_user 释放后继续使用, 可提权
 * 触发条件: ioctl 竞争导致 timer 对象 free 后仍被引用
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct timer_obj {
    int id;
    char name[16];
};

struct timer_user {
    struct timer_obj *timer;
    int active;
};

void release_timer(struct timer_user *u) {
    free(u->timer);          /* free 后未置 NULL */
    u->active = 0;
}

int use_timer(struct timer_user *u) {
    if (!u->active) return -1;
    return u->timer->id;     /* UAF: timer 可能已 free */
}

int main(int argc, char **argv) {
    struct timer_user *u = (struct timer_user *)malloc(sizeof(*u));
    u->timer = (struct timer_obj *)malloc(sizeof(struct timer_obj));
    u->timer->id = 7;
    strcpy(u->timer->name, "timer0");
    u->active = 1;
    release_timer(u);
    /* 缺陷: 未检查 active 即使用 timer */
    printf("timer id: %d\n", use_timer(u));
    free(u);
    return 0;
}
