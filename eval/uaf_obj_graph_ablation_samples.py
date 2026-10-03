"""

覆盖单函数/路径敏感/跨函数/CVE模拟四类UAF场景.
"""
from __future__ import annotations
from typing import Dict, List, Tuple

# 单函数样本
INTRA_SAMPLES: List[Tuple[str, str, str]] = [
    ('intr_simple', """
char *p = malloc(64);
*p = 1;
free(p);
*p = 2;
""", 'CONFIRMED'),
    ('intr_alias', """
char *p = malloc(64);
char *q = p;
free(p);
*q = 42;
""", 'CONFIRMED'),
    ('intr_realloc_old', """
char *p = malloc(64);
char *q = realloc(p, 128);
*p = 1;
""", 'CONFIRMED'),
    ('intr_field_alias', """
struct node { struct node *next; int val; };
struct node *n = malloc(sizeof(struct node));
struct node *m = n;
free(n);
m->val = 42;
""", 'CONFIRMED'),
    ('edge_null_check', """
char *p = malloc(64);
free(p);
if (p) {
    *p = 1;
}
""", 'CONFIRMED'),
    ('edge_nullify', """
char *p = malloc(64);
free(p);
p = NULL;
*p = 1;
""", 'SAFE'),
    ('edge_realloc_new', """
char *p = malloc(64);
char *q = realloc(p, 128);
*q = 1;
p = NULL;
""", 'SAFE'),
    ('edge_strdup', """
char *orig = strdup("hello");
free(orig);
*orig = 'x';
""", 'CONFIRMED'),
    ('fp_diff_obj', """
char *p = malloc(64);
char *q = malloc(64);
free(p);
*q = 1;
""", 'SAFE'),
    ('fp_safe_realloc', """
char *p = malloc(64);
char *q = realloc(p, 128);
q[0] = 42;
""", 'SAFE'),
    ('fp_refcount', """
struct obj { int refcount; char *data; };
struct obj *o = malloc(sizeof(struct obj));
o->data = malloc(128);
free(o);
""", 'SAFE'),
]

# 路径敏感样本
PATH_SAMPLES: List[Tuple[str, str, str]] = [
    ('path_branch_free', """
char *p = malloc(64);
if (error) {
    free(p);
    p = NULL;
}
*p = 1;
""", 'SAFE'),
    ('path_same_path', """
char *p = malloc(64);
if (error) {
    free(p);
    *p = 2;
}
""", 'CONFIRMED'),
    ('path_both_branches', """
char *p = malloc(64);
if (cond) {
    free(p);
} else {
    free(p);
}
*p = 1;
""", 'CONFIRMED'),
    ('path_reassign', """
char *p = malloc(64);
free(p);
p = malloc(128);
*p = 1;
""", 'SAFE'),
]

# 跨函数样本 (func_name → code, call_edges, expected)
CROSS_SAMPLES: List[Tuple[str, Dict[str, str], List[Tuple[str, str]], str]] = [
    ('cross_callee_frees',
     {'helper': 'void helper(char *buf) { free(buf); }',
      'caller': 'void caller() {\n    char *p = malloc(64);\n    helper(p);\n    *p = 1;\n}'},
     [('caller', 'helper')], 'CONFIRMED'),
    ('cross_param_prop',
     {'inner_free': 'void inner_free(char *x) { free(x); }',
      'middle': 'void middle(char *y) { inner_free(y); }',
      'outer': 'void outer() {\n    char *buf = malloc(128);\n    middle(buf);\n    buf[0] = 42;\n}'},
     [('outer', 'middle'), ('middle', 'inner_free')], 'CONFIRMED'),
    ('cross_return_freed',
     {'create_and_free': 'char *create_and_free() {\n    char *p = malloc(64);\n    free(p);\n    return p;\n}',
      'use_returned': 'void use_returned() {\n    char *q = create_and_free();\n    *q = 0;\n}'},
     [('use_returned', 'create_and_free')], 'CONFIRMED'),
    ('cross_callback',
     {'register_free': 'void register_free(char *ptr) { free(ptr); }',
      'dispatch': 'void dispatch() {\n    char *data = malloc(256);\n    register_free(data);\n    data[0] = 0;\n}'},
     [('dispatch', 'register_free')], 'CONFIRMED'),
    ('cross_return_live',
     {'make_obj': 'char *make_obj() {\n    char *p = malloc(64);\n    return p;\n}',
      'use_obj': 'void use_obj() {\n    char *q = make_obj();\n    q[0] = 1;\n}'},
     [('use_obj', 'make_obj')], 'SAFE'),
    ('cross_reassign_safe',
     {'clear': 'void clear(char *ptr) { free(ptr); }',
      'work': 'void work() {\n    char *buf = malloc(64);\n    clear(buf);\n    buf = malloc(128);\n    buf[0] = 1;\n}'},
     [('work', 'clear')], 'SAFE'),
    ('cross_deep_chain',
     {'leaf_free': 'void leaf_free(char *data) { free(data); }',
      'mid_process': 'void mid_process(char *item) { leaf_free(item); }',
      'top_handler': 'void top_handler() {\n    char *obj = malloc(256);\n    mid_process(obj);\n    obj->field = 0;\n}'},
     [('top_handler', 'mid_process'), ('mid_process', 'leaf_free')], 'CONFIRMED'),
    ('cross_cache_reuse',
     {'cache_flush': 'void cache_flush(struct cache_entry *e) { free(e->data); }',
      'use_cache': 'void use_cache() {\n    struct cache_entry *e = malloc(sizeof(struct cache_entry));\n    e->data = malloc(256);\n    cache_flush(e);\n    e->data[0] = 1;\n}'},
     [('use_cache', 'cache_flush')], 'CONFIRMED'),
]

# CVE 模拟跨函数样本
CVE_SAMPLES: List[Tuple[str, Dict[str, str], List[Tuple[str, str]], str]] = [
    ('cve_callback_uaf',
     {'release': 'void release(void *p) { free(p); }',
      'trigger': 'void trigger() {\n    char *buf = malloc(128);\n    release(buf);\n    buf[0] = 1;\n}'},
     [('trigger', 'release')], 'CONFIRMED'),
    ('cve_chained_free',
     {'free_node': 'void free_node(struct node *n) { free(n); }',
      'delete_list': 'void delete_list(struct node *head) { free_node(head); }',
      'caller': 'void caller() {\n    struct node *h = malloc(sizeof(struct node));\n    delete_list(h);\n    h->next = NULL;\n}'},
     [('caller', 'delete_list'), ('delete_list', 'free_node')], 'CONFIRMED'),
    ('cve_obj_cache_reuse',
     {'cache_flush': 'void cache_flush(struct cache_entry *e) { free(e->data); }',
      'use_cache': 'void use_cache() {\n    struct cache_entry *e = malloc(sizeof(struct cache_entry));\n    e->data = malloc(256);\n    cache_flush(e);\n    e->data[0] = 0;\n}'},
     [('use_cache', 'cache_flush')], 'CONFIRMED'),
]


__all__ = [
    'INTRA_SAMPLES', 'PATH_SAMPLES', 'CROSS_SAMPLES', 'CVE_SAMPLES',
]
