"""
UAF 对象身份图增强回归测试 — C 样本常量.

路径敏感 / 跨过程传播 / 调用图 / CVE 模拟样本字符串.
"""

# 路径敏感测试样本 — 条件分支中的 free/use

PATH_FREE_IN_BRANCH_USE_OUTSIDE = """
char *p = malloc(64);
if (error) {
    free(p);
    p = NULL;
}
*p = 1;
"""

PATH_FREE_USE_SAME_PATH = """
char *p = malloc(64);
if (error) {
    free(p);
    *p = 2;
}
"""

PATH_FREE_IN_BOTH_BRANCHES = """
char *p = malloc(64);
if (cond) {
    free(p);
} else {
    free(p);
}
*p = 1;
"""

PATH_REASSIGN_AFTER_FREE = """
char *p = malloc(64);
free(p);
p = malloc(128);
*p = 1;
"""


# 跨过程传播测试样本 — 使用新 Propagator

INTERPROC_CALLEE_FREES_PARAM = """
void destroy(char *obj) {
    free(obj);
}
void process() {
    char *buf = malloc(64);
    destroy(buf);
    buf[0] = 'A';
}
"""

INTERPROC_DEEP_CHAIN = """
void leaf_free(char *data) {
    free(data);
}
void mid_process(char *item) {
    leaf_free(item);
}
void top_handler() {
    char *obj = malloc(256);
    mid_process(obj);
    obj->field = 0;
}
"""

INTERPROC_RETURN_LIVE = """
char *make_obj() {
    char *p = malloc(64);
    return p;
}
void use_obj() {
    char *q = make_obj();
    q[0] = 'x';
}
"""

INTERPROC_REUSE_AFTER_FREE = """
void clear(char *ptr) {
    free(ptr);
}
void work() {
    char *buf = malloc(64);
    clear(buf);
    buf = malloc(128);
    buf[0] = 1;
}
"""


# 调用图测试样本

CG_MULTI_CALL = """
void sink(char *p) {
    free(p);
}
void caller_a() {
    char *a = malloc(32);
    sink(a);
    a[0] = 1;
}
void caller_b() {
    char *b = malloc(64);
    sink(b);
    *b = 2;
}
"""

CG_PARAMS = """
void process(int x, char *buf, int len) {
    free(buf);
}
void main_func() {
    char *data = malloc(128);
    process(0, data, 128);
    data[0] = 'A';
}
"""


# CVE 模拟样本

CVE_OBJ_CACHE_REUSE = """
struct cache_entry { char *data; int size; };
void cache_flush(struct cache_entry *e) {
    free(e->data);
}
void use_cache() {
    struct cache_entry *e = malloc(sizeof(struct cache_entry));
    e->data = malloc(256);
    cache_flush(e);
    e->data[0] = 'x';
}
"""

CVE_CALLBACK_UAF = """
typedef void (*release_fn)(void *);
void release(void *p) {
    free(p);
}
void register_cb(release_fn cb) {
}
void trigger() {
    char *buf = malloc(128);
    register_cb(release);
    release(buf);
    buf[0] = 1;
}
"""

CVE_DOUBLE_FREE = """
char *p = malloc(64);
*p = 1;
free(p);
free(p);
"""

CVE_REINIT_AFTER_FREE = """
struct list { struct list *next; };
struct list *head = malloc(sizeof(struct list));
head->next = NULL;
free(head);
head->next = NULL;
"""

CVE_CHAINED_FREE = """
void free_node(struct node *n) {
    free(n);
}
void delete_list(struct node *head) {
    free_node(head);
}
void caller() {
    struct node *h = malloc(sizeof(struct node));
    delete_list(h);
    h->next = NULL;
}
"""


# 测试方法内联函数体 — TestHoigCallGraph

CG_MAIN_SRC = (
    'void main() {\n'
    '    char *q = make_obj();\n'
    '    destroy(q);\n'
    '}\n'
)
CG_CALLER_SRC = (
    'void caller() {\n'
    '    char *p = malloc(64);\n'
    '    helper(p);\n'
    '    *p = 1;\n'
    '}\n'
)


# 测试方法内联函数体 — TestInterprocPropagator

PROP_DESTROY_SRC = 'void destroy(char *obj) {\n free(obj);\n}'
PROP_PROCESS_SRC = (
    'void process() {\n'
    '    char *buf = malloc(64);\n'
    '    destroy(buf);\n'
    "    buf[0] = 'A';\n"
    '}\n'
)
PROP_LEAF_FREE_SRC = 'void leaf_free(char *data) {\n free(data);\n}'
PROP_MID_PROCESS_SRC = 'void mid_process(char *item) {\n leaf_free(item);\n}'
PROP_TOP_HANDLER_SRC = (
    'void top_handler() {\n'
    '    char *obj = malloc(256);\n'
    '    mid_process(obj);\n'
    '    obj->field = 0;\n'
    '}\n'
)
PROP_MAKE_OBJ_SRC = (
    'char *make_obj() {\n'
    '    char *p = malloc(64);\n'
    '    return p;\n'
    '}\n'
)
PROP_USE_OBJ_SRC = (
    'void use_obj() {\n'
    '    char *q = make_obj();\n'
    "    q[0] = 'x';\n"
    '}\n'
)
PROP_CLEAR_SRC = 'void clear(char *ptr) {\n free(ptr);\n}'
PROP_WORK_SRC = (
    'void work() {\n'
    '    char *buf = malloc(64);\n'
    '    clear(buf);\n'
    '    buf = malloc(128);\n'
    '    buf[0] = 1;\n'
    '}\n'
)


# 测试方法内联函数体 — TestCVESimulation

PROP_CACHE_FLUSH_SRC = (
    'void cache_flush(struct cache_entry *e) {\n'
    '    free(e->data);\n'
    '}\n'
)
PROP_USE_CACHE_SRC = (
    'void use_cache() {\n'
    '    struct cache_entry *e = malloc(sizeof(struct cache_entry));\n'
    '    e->data = malloc(256);\n'
    '    cache_flush(e);\n'
    "    e->data[0] = 'x';\n"
    '}\n'
)
CV_TRIGGER_SRC = (
    'void trigger() {\n'
    '    char *buf = malloc(128);\n'
    '    release(buf);\n'
    '    buf[0] = 1;\n'
    '}\n'
)
CV_DELETE_LIST_SRC = 'void delete_list(struct node *head) { free_node(head); }'
CV_CALLER_CHAINED_SRC = (
    'void caller() {\n'
    '    struct node *h = malloc(sizeof(struct node));\n'
    '    delete_list(h);\n'
    '    h->next = NULL;\n'
    '}\n'
)
