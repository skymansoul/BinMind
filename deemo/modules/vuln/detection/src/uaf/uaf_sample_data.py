"""UAF 测试样本数据 — 18 个 C 源码 UAF 模式定义.

创建: 2025-01-13
      14 TP (各种UAF模式) + 4 TN (安全对照).
"""

UAF_SAMPLES = [
    {
        'id': 'sample01_basic_uaf',
        'title': 'Basic Use-After-Free',
        'pattern': 'malloc(64) → free → use (deref)',
        'expected': 'TP',
        'trigger': 'free(buf); then *buf = X',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    strcpy(buf, "hello");
    free(buf);
    /* UAF: write to freed buffer */
    buf[0] = 'H';
    printf("uaf: %s\n", buf);
    return 0;
}
''',
    },
    {
        'id': 'sample02_double_free',
        'title': 'Double Free',
        'pattern': 'malloc → free → free (double free) → use',
        'expected': 'TP',
        'trigger': 'free(buf); free(buf); *buf = X',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(sizeof(int) * 16);
    if (!p) return 1;
    *p = 42;
    free(p);
    /* double free → undefined behavior, UAF after */
    free(p);
    printf("double-freed: %d\n", *p);
    return 0;
}
''',
    },
    {
        'id': 'sample03_realloc_uaf',
        'title': 'Realloc UAF — use old pointer after realloc',
        'pattern': 'malloc(32) → realloc(p, 64) → use old ptr',
        'expected': 'TP',
        'trigger': 'p2 = realloc(p, new_size); *p = X',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *old = (char *)malloc(32);
    if (!old) return 1;
    strcpy(old, "data");
    /* realloc may free old and return new block */
    char *new_buf = (char *)realloc(old, 64);
    if (new_buf) {
        /* UAF: old pointer still used */
        old[0] = 'X';
        printf("old=%s new=%s\n", old, new_buf);
    }
    free(new_buf);
    return 0;
}
''',
    },
    {
        'id': 'sample04_cross_function_uaf',
        'title': 'Cross-Function UAF — caller frees, callee uses',
        'pattern': 'malloc in caller → free in caller → callee uses freed ptr',
        'expected': 'TP',
        'trigger': 'free(buf); process_buffer(buf)',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void use_buffer(char *p) {
    p[0] = 'U';  /* UAF: p already freed by caller */
    printf("used: %c\n", p[0]);
}

int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "cross_function");
    free(buf);
    use_buffer(buf);  /* UAF: pass freed ptr to function */
    return 0;
}
''',
    },
    {
        'id': 'sample05_alias_uaf',
        'title': 'Alias UAF — use alias after original freed',
        'pattern': 'p2 = p1; free(p1); *p2 = X',
        'expected': 'TP',
        'trigger': 'alias = orig; free(orig); *alias = X',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *orig = (int *)malloc(sizeof(int) * 8);
    int *alias = orig;  /* alias points to same block */
    if (!orig) return 1;
    orig[0] = 100;
    free(orig);
    /* UAF: alias still points to freed memory */
    alias[0] = 200;
    printf("alias[0] = %d\n", alias[0]);
    return 0;
}
''',
    },
    {
        'id': 'sample06_struct_field_uaf',
        'title': 'Struct Field UAF — free struct member, use via struct',
        'pattern': 's.ptr = malloc; free(s.ptr); *s.ptr = X',
        'expected': 'TP',
        'trigger': 'free(obj->data); obj->data[0] = X',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char *data;
    int len;
} Buffer;

int main(void) {
    Buffer b;
    b.data = (char *)malloc(64);
    b.len = 64;
    if (!b.data) return 1;
    b.data[0] = 'A';
    free(b.data);
    /* UAF: access freed member through struct */
    b.data[0] = 'B';
    printf("freed field: %c\n", b.data[0]);
    return 0;
}
''',
    },
    {
        'id': 'sample07_conditional_uaf',
        'title': 'Conditional UAF — free in one branch, use in another',
        'pattern': 'if (flag) { free(p); } *p = X',
        'expected': 'TP',
        'trigger': 'conditional free → unconditional use',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "conditional");
    if (argc > 1) {
        free(p);  /* free only when argv present */
    }
    /* UAF: unconditional use after conditional free */
    p[0] = 'C';
    printf("conditional: %s\n", p);
    return 0;
}
''',
    },
    {
        'id': 'sample08_loop_uaf',
        'title': 'Loop UAF — free in loop, use in subsequent iteration',
        'pattern': 'for (...) { free(items[i]); process(items[i-1]); }',
        'expected': 'TP',
        'trigger': 'free in iteration N, use iteration N-1 in N+1',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buffers[4];
    for (int i = 0; i < 4; i++) {
        buffers[i] = (char *)malloc(32);
        if (buffers[i]) sprintf(buffers[i], "buf%d", i);
    }
    for (int i = 0; i < 4; i++) {
        free(buffers[i]);
        if (i > 0) {
            /* UAF: buffers[i-1] already freed */
            printf("prev: %s\n", buffers[i-1]);
        }
    }
    return 0;
}
''',
    },
    {
        'id': 'sample09_list_node_uaf',
        'title': 'Linked List Node UAF',
        'pattern': 'free node; traverse node->next',
        'expected': 'TP',
        'trigger': 'free(node); node = node->next',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

typedef struct Node {
    int val;
    struct Node *next;
} Node;

int main(void) {
    Node *head = (Node *)malloc(sizeof(Node));
    Node *mid = (Node *)malloc(sizeof(Node));
    Node *tail = (Node *)malloc(sizeof(Node));
    if (!head || !mid || !tail) return 1;
    head->val = 1; head->next = mid;
    mid->val = 2; mid->next = tail;
    tail->val = 3; tail->next = NULL;
    free(mid);
    /* UAF: head->next is freed mid */
    printf("skipped free node: %d\n", head->next->val);
    free(head);
    free(tail);
    return 0;
}
''',
    },
    {
        'id': 'sample10_callback_uaf',
        'title': 'Callback UAF — register ptr, free, callback fires',
        'pattern': 'register callback(p); free(p); callback fires → *p',
        'expected': 'TP',
        'trigger': 'callback registered before free, invoked after',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

typedef void (*cb_t)(int *);

static int *global = NULL;
static cb_t saved_cb = NULL;

void my_callback(int *data) {
    *data = 999;  /* UAF: data could be freed */
    printf("callback: %d\n", *data);
}

int main(void) {
    int *data = (int *)malloc(sizeof(int) * 4);
    if (!data) return 1;
    *data = 42;
    global = data;
    saved_cb = my_callback;
    free(global);
    /* UAF: callback uses freed data */
    if (saved_cb) saved_cb(global);
    return 0;
}
''',
    },
    {
        'id': 'sample11_realloc_zero_uaf',
        'title': 'Realloc(0) UAF — realloc to zero size returns NULL',
        'pattern': 'realloc(p, 0) returns NULL → *p is UAF (glibc)',
        'expected': 'TP',
        'trigger': 'realloc(p, 0) → use p',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(128);
    if (!p) return 1;
    strcpy(p, "zero_realloc");
    /* realloc(p, 0) — implementation-defined: may free or return NULL */
    char *q = (char *)realloc(p, 0);
    if (q == NULL) {
        /* UAF: original p may have been freed */
        p[0] = 'Z';
        printf("zero-realloc uaf: %c\n", p[0]);
    }
    return 0;
}
''',
    },
    {
        'id': 'sample12_vector_uaf',
        'title': 'Vector Reallocation UAF — resize invalidates pointers',
        'pattern': 'push_back causes realloc → old ptr still used',
        'expected': 'TP',
        'trigger': 'resize → old ptr becomes dangling',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    int *vec = (int *)malloc(sizeof(int) * 2);
    if (!vec) return 1;
    vec[0] = 10; vec[1] = 20;
    int *old_ptr = &vec[1];  /* points into vec */
    /* realloc vec — old_ptr may become dangling */
    int *new_vec = (int *)realloc(vec, sizeof(int) * 8);
    if (new_vec) {
        vec = new_vec;
        /* UAF: old_ptr still points to old allocation */
        *old_ptr = 99;
        printf("stale ref: %d\n", *old_ptr);
    }
    free(vec);
    return 0;
}
''',
    },
    {
        'id': 'sample13_multi_free_uaf',
        'title': 'Multi-Free in Error Path',
        'pattern': 'complex error handling → multiple frees → stale use',
        'expected': 'TP',
        'trigger': 'free in error handler then normal path uses ptr',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cleanup(char *a, char *b) {
    if (a) free(a);
    if (b) free(b);
}

int main(void) {
    char *x = (char *)malloc(64);
    char *y = (char *)malloc(64);
    if (!x || !y) {
        free(x); free(y);
        return 1;
    }
    strcpy(x, "error_path");
    /* x freed inside cleanup */
    cleanup(x, NULL);
    /* UAF: x freed but reused */
    printf("after cleanup: %s\n", x);
    free(y);
    return 0;
}
''',
    },
    {
        'id': 'sample14_thread_uaf',
        'title': 'Thread-like UAF — free before async use',
        'pattern': 'free object while it is still referenced in queue',
        'expected': 'TP',
        'trigger': 'free(task); queue still has task ptr',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char *payload;
} Task;

static Task *task_queue[4];

int main(void) {
    Task *t = (Task *)malloc(sizeof(Task));
    if (!t) return 1;
    t->id = 1;
    t->payload = (char *)malloc(32);
    if (t->payload) strcpy(t->payload, "work");
    task_queue[0] = t;
    /* UAF: free task but queue still references it */
    free(t->payload);
    free(t);
    printf("queued task id=%d\n", task_queue[0]->id);
    return 0;
}
''',
    },
    {
        'id': 'sample15_null_after_free_safe',
        'title': 'Safe: Null After Free (not UAF)',
        'pattern': 'free(p); p = NULL → no UAF possible',
        'expected': 'TN',
        'trigger': 'p set to NULL after free → safe',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "safe_null");
    free(p);
    p = NULL;  /* safe: null after free */
    if (p) {
        p[0] = 'X';  /* unreachable */
    }
    printf("null after free: safe\n");
    return 0;
}
''',
    },
    {
        'id': 'sample16_guard_before_use_safe',
        'title': 'Safe: Guard Check Before Use (not UAF)',
        'pattern': 'if (ptr != NULL) { free(ptr); ptr = NULL; } → safe',
        'expected': 'TN',
        'trigger': 'null check before every use',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *data = (int *)malloc(sizeof(int) * 10);
    if (!data) return 1;
    for (int i = 0; i < 10; i++) data[i] = i;
    free(data);
    data = NULL;
    /* safe: always null-checked after potential free */
    if (data != NULL) {
        data[0] = 999;  /* unreachable */
    }
    printf("guarded: safe\n");
    return 0;
}
''',
    },
    {
        'id': 'sample17_copy_then_free_safe',
        'title': 'Safe: Copy Before Free (not UAF)',
        'pattern': 'save value → free → use saved copy → no UAF',
        'expected': 'TN',
        'trigger': 'value copied before free, original not used',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *src = (char *)malloc(64);
    if (!src) return 1;
    sprintf(src, "value is %d", 42);
    /* copy value before free */
    int saved = src[0];
    free(src);
    /* safe: uses saved copy, not freed ptr */
    printf("saved value: %c\n", (char)saved);
    return 0;
}
''',
    },
    {
        'id': 'sample18_realloc_same_ptr_safe',
        'title': 'Safe: Realloc Same Pointer — use new ptr (not UAF)',
        'pattern': 'new = realloc(old, larger); use new → safe',
        'expected': 'TN',
        'trigger': 'new pointer correctly used, old discarded',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    strcpy(p, "hello");
    /* safe: use returned pointer from realloc */
    char *q = (char *)realloc(p, 128);
    if (!q) { free(p); return 1; }
    strcat(q, " world");
    printf("realloc safe: %s\n", q);
    free(q);
    return 0;
}
''',
    },
]
