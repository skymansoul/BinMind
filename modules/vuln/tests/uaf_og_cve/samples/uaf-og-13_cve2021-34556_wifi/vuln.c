/* CVE-2021-34556 (Linux wifi) UAF 复现 — cfg80211 扫描请求释放后
   wdev 仍被使用. 简化: free(p) 后经全局链解引用. */

#include <stdio.h>
#include <stdlib.h>

struct wdev {
    struct wdev *next;
    int ifindex;
};

static struct wdev *head;

int main(void) {
    struct wdev *w;
    w = (struct wdev *)malloc(sizeof(struct wdev));
    if (!w) {
        return 1;
    }
    w->ifindex = 3;
    head = w;
    free(w);
    if (head) {
        printf("%d\n", head->ifindex);
    }
    return 0;
}
