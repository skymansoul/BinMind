"""
HOIG 回归测试 C 样本 — 堆对象身份追踪 UAF 检测.

样本分类:
  - INTR_FUNC (4):  单函数内 UAF
  - CROSS_FUNC (4): 跨函数 UAF
  - EDGE (4):       边界情况
  - FP_FILTER (3):  误报过滤
"""

# 单函数内 UAF (INTR_FUNC)

INTR_SIMPLE = """
char *p = malloc(64);
*p = 1;
free(p);
*p = 2;
"""

INTR_ALIAS = """
char *p = malloc(64);
char *q = p;
free(p);
*q = 42;
"""

INTR_REALLOC_OLD_PTR = """
char *p = malloc(64);
char *q = realloc(p, 128);
*p = 1;
"""

INTR_FIELD_ALIAS = """
struct node { struct node *next; int val; };
struct node *n = malloc(sizeof(struct node));
struct node *m = n;
free(n);
m->val = 42;
"""

# 跨函数 UAF (CROSS_FUNC)

CROSS_CALLEE_FREES = """
void helper(char *buf) {
    free(buf);
}
void caller() {
    char *p = malloc(64);
    helper(p);
    *p = 1;
}
"""

CROSS_PARAM_PROPAGATION = """
void inner_free(char *x) {
    free(x);
}
void middle(char *y) {
    inner_free(y);
}
void outer() {
    char *buf = malloc(128);
    middle(buf);
    buf[0] = 42;
}
"""

CROSS_RETURN_FREED = """
char *create_and_free() {
    char *p = malloc(64);
    free(p);
    return p;
}
void use_returned() {
    char *q = create_and_free();
    *q = 0;
}
"""

CROSS_CALLBACK = """
typedef void (*cb_t)(char *);
void register_free(char *ptr) {
    free(ptr);
}
void dispatch() {
    char *data = malloc(256);
    register_free(data);
    data[0] = 'x';
}
"""

# 边界情况 (EDGE)

EDGE_NULL_CHECK_AFTER_FREE = """
char *p = malloc(64);
free(p);
if (p) {
    *p = 1;
}
"""

EDGE_NULLIFY_AFTER_FREE = """
char *p = malloc(64);
free(p);
p = NULL;
*p = 1;
"""

EDGE_REALLOC_NEW_PTR_USE = """
char *p = malloc(64);
char *q = realloc(p, 128);
*q = 1;
p = NULL;
"""

EDGE_STRDUP_UAF = """
char *orig = strdup("hello");
free(orig);
*orig = 'x';
"""

# 误报过滤 (FP_FILTER) — 不应标记为 UAF

FP_DIFFERENT_OBJ = """
char *p = malloc(64);
char *q = malloc(64);
free(p);
*q = 1;
"""

FP_SAFE_REALLOC = """
char *p = malloc(64);
char *q = realloc(p, 128);
q[0] = 42;
"""

FP_REFCOUNT_RESET = """
struct obj { int refcount; char *data; };
struct obj *o = malloc(sizeof(struct obj));
o->data = malloc(128);
free(o);
"""

# 基准测试期望映射

BENCHMARK_SAMPLES = {
    'intr_simple':          INTR_SIMPLE,
    'intr_alias':           INTR_ALIAS,
    'intr_realloc_old_ptr': INTR_REALLOC_OLD_PTR,
    'intr_field_alias':     INTR_FIELD_ALIAS,
    'edge_null_check':      EDGE_NULL_CHECK_AFTER_FREE,
    'edge_nullify':         EDGE_NULLIFY_AFTER_FREE,
    'edge_realloc_new':     EDGE_REALLOC_NEW_PTR_USE,
    'edge_strdup':          EDGE_STRDUP_UAF,
    'fp_diff_obj':          FP_DIFFERENT_OBJ,
    'fp_safe_realloc':      FP_SAFE_REALLOC,
    'fp_refcount':          FP_REFCOUNT_RESET,
}

BENCHMARK_EXPECTED = {
    'intr_simple':          'CONFIRMED',
    'intr_alias':           'CONFIRMED',
    'intr_realloc_old_ptr': 'CONFIRMED',
    'intr_field_alias':     'CONFIRMED',
    'edge_null_check':      'CONFIRMED',
    'edge_nullify':         'SAFE',
    'edge_realloc_new':     'SAFE',
    'edge_strdup':          'CONFIRMED',
    'fp_diff_obj':          'SAFE',
    'fp_safe_realloc':      'SAFE',
    'fp_refcount':          'SAFE',
}
