#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-11: 模拟多线程竞态UAF — 释放和使用时间窗口重叠 */
#include <unistd.h>
static char *shared = NULL;

void do_work(void) {
    shared = (char *)malloc(64);
    if (!shared) return;
    strcpy(shared, "thread_shared_data");
    free(shared);  /* 释放共享指针, 但并发线程可能仍在使用 */
}
int main(void) {
    do_work();
    /* 模拟: do_work释放后主线程仍访问 */
    if (shared) printf("shared: %s\n", shared);  /* VULNERABLE */
    return 0;
}
