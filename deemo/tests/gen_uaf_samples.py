"""生成15个UAF测试样本 — 每个独立目录，含vuln.c + Makefile + README.md。"""
import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples', 'uaf')
SAMPLE_DIRS = sorted([d for d in os.listdir(BASE) if os.path.isdir(os.path.join(BASE, d))])

from tests.gen_uaf_samples_data import C_SOURCES, MAKEFILE

# 合并剩余C样本 (7-15)
C_SOURCES_REMAINING = {
    'uaf_array_index': r'''#include <stdio.h>
#include <stdlib.h>
/* UAF-07: 数组中的对象指针 — 释放后通过数组索引访问 */
#define COUNT 8
typedef struct { int val; char *label; } Elem;
int main(void) {
    Elem *arr[COUNT];
    for (int i = 0; i < COUNT; i++) {
        arr[i] = (Elem *)malloc(sizeof(Elem));
        arr[i]->val = i * 10;
    }
    for (int i = 0; i < COUNT; i++) free(arr[i]);
    printf("val=%d\n", arr[3]->val);  /* VULNERABLE: arr[3]已释放 */
    return 0;
}
''',
    'uaf_callback_free': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-08: 回调中的UAF — free后仍注册为callback被调用 */
typedef void (*cb_t)(void *);
static cb_t g_callback = NULL;
static void *g_ctx = NULL;
void register_cb(cb_t cb, void *ctx) { g_callback = cb; g_ctx = ctx; }
void my_handler(void *ctx) { printf("handler: %s\n", (char *)ctx); }

int main(void) {
    char *data = (char *)malloc(64);
    if (!data) return 1;
    strcpy(data, "callback_context");
    register_cb(my_handler, data);
    free(data);  /* 释放context但未取消注册 */
    if (g_callback) g_callback(g_ctx);  /* VULNERABLE: g_ctx已释放 */
    return 0;
}
''',
    'uaf_list_node': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-09: 链表节点UAF — 节点被free后继续遍历 */
typedef struct Node { int id; char data[32]; struct Node *next; } Node;
int main(void) {
    Node *head = (Node *)malloc(sizeof(Node));
    head->id = 1; strcpy(head->data, "first");
    head->next = (Node *)malloc(sizeof(Node));
    head->next->id = 2; strcpy(head->next->data, "second");
    head->next->next = NULL;
    free(head->next);  /* 释放第二个节点 */
    Node *cur = head;
    while (cur) {
        printf("node %d: %s\n", cur->id, cur->data);
        cur = cur->next;  /* VULNERABLE: cur->next已释放 */
    }
    free(head);
    return 0;
}
''',
    'uaf_queue_pop': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-10: 队列pop后的UAF — 出队元素被释放但外部仍持有引用 */
typedef struct QNode { char *msg; struct QNode *next; } QNode;
static QNode *queue = NULL;
void push(const char *m) {
    QNode *n = (QNode *)malloc(sizeof(QNode));
    n->msg = strdup(m); n->next = queue; queue = n;
}
QNode *pop(void) {
    if (!queue) return NULL;
    QNode *n = queue; queue = queue->next; return n;
}

int main(void) {
    push("msg_one"); push("msg_two");
    QNode *item = pop();
    printf("popped: %s\n", item->msg);
    free(item->msg); free(item);
    printf("use after pop: %s\n", item->msg);  /* VULNERABLE */
    QNode *item2 = pop();
    if (item2) { free(item2->msg); free(item2); }
    return 0;
}
''',
    'uaf_thread_race_sim': r'''#include <stdio.h>
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
''',
    'uaf_signal_handler': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
/* UAF-12: 信号处理器中的UAF — 信号触发时访问已释放的全局指针 */
static char *g_data = NULL;
void sig_handler(int sig) {
    if (g_data) printf("signal: %s\n", g_data);  /* 可能在free后触发 */
}
int main(void) {
    g_data = (char *)malloc(128);
    if (!g_data) return 1;
    strcpy(g_data, "signal_data");
    signal(SIGUSR1, sig_handler);
    free(g_data);  /* 释放后若信号到达, handler访问悬挂指针 */
    printf("freed g_data, send SIGUSR1 to trigger\n");
    return 0;
}
''',
    'uaf_nested_free': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-13: 嵌套结构释放 — 外层free后内层指针仍可被访问 */
typedef struct { int count; char **items; } Container;
int main(void) {
    Container *c = (Container *)malloc(sizeof(Container));
    c->count = 3;
    c->items = (char **)malloc(3 * sizeof(char *));
    for (int i = 0; i < 3; i++) {
        c->items[i] = (char *)malloc(16);
        sprintf(c->items[i], "item_%d", i);
    }
    /* 先释放items, 再释放container — 但顺序错 */
    free(c);  /* 外层先释放了! */
    for (int i = 0; i < 3; i++)
        printf("%s\n", c->items[i]);  /* VULNERABLE: c已释放 */
    for (int i = 0; i < 3; i++) free(c->items[i]);
    free(c->items);
    return 0;
}
''',
    'uaf_mmap_free': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
/* UAF-14: mmap/munmap的UAF — 非堆分配释放后访问 */
int main(void) {
    long pgsize = sysconf(_SC_PAGESIZE);
    char *buf = (char *)mmap(NULL, pgsize, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) return 1;
    strcpy(buf, "mmap_data");
    munmap(buf, pgsize);
    printf("after munmap: %s\n", buf);  /* VULNERABLE: munmap后访问 */
    return 0;
}
''',
    'uaf_interproc_sim': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-15: 跨函数UAF — free发生在子函数中, use发生在调用者中 */
static char *global = NULL;

void allocate(void) {
    global = (char *)malloc(100);
    if (global) strcpy(global, "interproc_data");
}
void cleanup(void) {
    if (global) { free(global); global = NULL; }
}
void bad_cleanup(void) {
    if (global) free(global);  /* 释放但不置NULL */
}

int main(int argc, char **argv) {
    allocate();
    if (argc > 1) bad_cleanup();
    else cleanup();
    /* bad_cleanup路径: global已释放但非NULL */
    if (global) printf("interproc: %s\n", global);  /* VULNERABLE if argc>1 */
    if (argc <= 1) free(global);
    return 0;
}
''',
}

C_SOURCES.update(C_SOURCES_REMAINING)

for name in SAMPLE_DIRS:
    d = os.path.join(BASE, name)
    src = C_SOURCES.get(name)
    if not src:
        print(f'  SKIP {name}: no C source defined')
        continue
    with open(os.path.join(d, 'vuln.c'), 'w', encoding='utf-8') as f:
        f.write(src)
    with open(os.path.join(d, 'Makefile'), 'w', encoding='utf-8') as f:
        f.write(MAKEFILE)
    with open(os.path.join(d, 'README.md'), 'w', encoding='utf-8') as f:
        f.write(f'# {name}\n')
        f.write(f'**CWE-416** — Use-After-Free\n\n')
        f.write(f'## Usage\n```bash\nmake && ./vuln\n```\n\n')
        f.write(f'## Detection Goal\n')
        f.write(f'BinMind TARPS pipeline should detect use-after-free in ')
        f.write(f'this sample while filtering safe pointer-nullify patterns.\n')
    print(f'  OK: {name}')

print(f'Done: {len(SAMPLE_DIRS)} UAF samples generated')
