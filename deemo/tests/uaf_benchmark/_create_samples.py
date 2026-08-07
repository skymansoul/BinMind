"""一键生成 UAF benchmark 样本集 — 12 样本 (6 TP + 6 TN)."""
import json, os

BASE = os.path.dirname(os.path.abspath(__file__))

SAMPLES = {}
SAMPLES['tp_01_direct_uaf'] = {
    'sample_id': 'TP-01', 'label': 'tp', 'cwe': 'CWE-416',
    'description': 'Direct UAF: free(buf) then printf(buf) — no NULL assignment',
    'expect_uaf': True, 'tarps_expected': 'DEF_TP',
    'code': '''/* TP-01: Direct Use-After-Free (CWE-416) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void process(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "sensitive data");
    free(buf);
    printf("%s\\n", buf);  /* UAF: buf used after free */
}
int main(void) { process(); return 0; }'''}

SAMPLES['tp_02_alias_uaf'] = {
    'sample_id': 'TP-02', 'label': 'tp', 'cwe': 'CWE-416',
    'description': 'Alias UAF: q=p; free(p); use(q)',
    'expect_uaf': True, 'tarps_expected': 'DEF_TP',
    'code': '''/* TP-02: Alias Use-After-Free (CWE-416) */
#include <stdlib.h>
typedef struct node { int id; struct node *next; } node_t;
void alias_uaf(void) {
    node_t *p = (node_t *)malloc(sizeof(node_t));
    if (!p) return;
    p->id = 42;
    node_t *q = p;
    free(p);
    q->id = 99;  /* UAF: q dangling */
}
int main(void) { alias_uaf(); return 0; }'''}

SAMPLES['tp_03_cross_func_uaf'] = {
    'sample_id': 'TP-03', 'label': 'tp', 'cwe': 'CWE-416',
    'description': 'Cross-function UAF: alloc in A, free in B, use in A',
    'expect_uaf': True, 'tarps_expected': 'DEF_TP',
    'code': '''/* TP-03: Cross-Function UAF (CWE-416) */
#include <stdlib.h>
#include <stdio.h>
static char *g_buf = NULL;
void alloc_buf(void) { g_buf = (char *)malloc(256); }
void free_buf(void) { if (g_buf) { free(g_buf); } }
void cross_uaf(void) {
    alloc_buf(); free_buf();
    printf("%c\\n", g_buf[0]);  /* UAF */
}
int main(void) { cross_uaf(); return 0; }'''}

SAMPLES['tp_04_realloc_alias_uaf'] = {
    'sample_id': 'TP-04', 'label': 'tp', 'cwe': 'CWE-416',
    'description': 'Realloc alias UAF: q=p; p=realloc(p,2n); use(q) — CVE-2023-28328 class',
    'expect_uaf': True, 'tarps_expected': 'DEF_TP',
    'code': '''/* TP-04: Realloc Alias UAF */
#include <stdlib.h>
#include <string.h>
typedef struct { int len; char data[64]; } buf_t;
void realloc_alias_uaf(void) {
    buf_t *p = (buf_t *)malloc(sizeof(buf_t));
    if (!p) return;
    p->len = 64;
    buf_t *q = p;
    p = (buf_t *)realloc(p, 128);
    memset(q->data, 0, 64);  /* UAF: q dangling after realloc */
}
int main(void) { realloc_alias_uaf(); return 0; }'''}

SAMPLES['tp_05_loop_uaf'] = {
    'sample_id': 'TP-05', 'label': 'tp', 'cwe': 'CWE-416',
    'description': 'Loop UAF: free inside loop, use after loop',
    'expect_uaf': True, 'tarps_expected': 'DEF_TP',
    'code': '''/* TP-05: Loop UAF (CWE-416) */
#include <stdlib.h>
#include <stdio.h>
typedef struct item { int id; struct item *next; } item_t;
void loop_uaf(item_t *head) {
    item_t *cur = head;
    while (cur) {
        item_t *next = cur->next;
        free(cur);
        cur = next;
    }
    printf("head id: %d\\n", head->id);  /* UAF */
}
int main(void) {
    item_t *a = (item_t *)malloc(sizeof(item_t));
    item_t *b = (item_t *)malloc(sizeof(item_t));
    a->id = 1; a->next = b; b->id = 2; b->next = NULL;
    loop_uaf(a); return 0;
}'''}

SAMPLES['tp_06_conditional_uaf'] = {
    'sample_id': 'TP-06', 'label': 'tp', 'cwe': 'CWE-416',
    'description': 'Conditional UAF: free in if-branch, use after merge',
    'expect_uaf': True, 'tarps_expected': 'DEF_TP',
    'code': '''/* TP-06: Conditional UAF (CWE-416) */
#include <stdlib.h>
void conditional_uaf(int do_free) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    if (do_free) { free(buf); }
    buf[0] = 'X';  /* UAF when do_free==1 */
}
int main(void) { conditional_uaf(1); return 0; }'''}

SAMPLES['tn_01_null_after_free'] = {
    'sample_id': 'TN-01', 'label': 'tn', 'cwe': 'NONE',
    'description': 'Safe: free(p); p=NULL; if(p) use(p) — NULL guard',
    'expect_uaf': False, 'tarps_expected': 'DEF_FP',
    'code': '''/* TN-01: NULL After Free (SAFE) */
#include <stdlib.h>
#include <stdio.h>
void null_after_free(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    free(buf);
    buf = NULL;
    if (buf != NULL) { printf("%s\\n", buf); }
}
int main(void) { null_after_free(); return 0; }'''}

SAMPLES['tn_02_reassign_after_free'] = {
    'sample_id': 'TN-02', 'label': 'tn', 'cwe': 'NONE',
    'description': 'Safe: free(p); p=malloc(n); use(p) — reassign after free',
    'expect_uaf': False, 'tarps_expected': 'DEF_FP',
    'code': '''/* TN-02: Reassign After Free (SAFE) */
#include <stdlib.h>
#include <string.h>
void reassign_after_free(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    free(buf);
    buf = (char *)malloc(128);
    strcpy(buf, "safe data");
    free(buf);
}
int main(void) { reassign_after_free(); return 0; }'''}

SAMPLES['tn_03_guarded_use'] = {
    'sample_id': 'TN-03', 'label': 'tn', 'cwe': 'NONE',
    'description': 'Safe: refcount guard prevents free; use protected by NULL check',
    'expect_uaf': False, 'tarps_expected': 'DEF_FP',
    'code': '''/* TN-03: Guarded Use with refcount (SAFE) */
#include <stdlib.h>
typedef struct { int refcount; char *data; } obj_t;
void guarded_free(obj_t *obj) {
    if (obj->refcount > 0) { obj->refcount--; return; }
    free(obj->data); obj->data = NULL;
}
void guarded_use(obj_t *obj) {
    if (obj && obj->data) { obj->data[0] = 'A'; }
}
int main(void) {
    obj_t *obj = (obj_t *)malloc(sizeof(obj_t));
    obj->refcount = 1;
    obj->data = (char *)malloc(32);
    guarded_free(obj); guarded_use(obj);
    free(obj->data); free(obj); return 0;
}'''}

SAMPLES['tn_04_realloc_self'] = {
    'sample_id': 'TN-04', 'label': 'tn', 'cwe': 'NONE',
    'description': 'Safe: p=realloc(p,2n); use(p) — self-assign, p updated',
    'expect_uaf': False, 'tarps_expected': 'DEF_FP',
    'code': '''/* TN-04: Realloc Self-Assign Safe (SAFE) */
#include <stdlib.h>
#include <string.h>
void realloc_self_safe(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    strcpy(p, "init");
    p = (char *)realloc(p, 128);
    strcat(p, " extended");
    free(p);
}
int main(void) { realloc_self_safe(); return 0; }'''}

SAMPLES['tn_05_branch_exclusive'] = {
    'sample_id': 'TN-05', 'label': 'tn', 'cwe': 'NONE',
    'description': 'Safe: free on branch A, use only on branch B — mutually exclusive',
    'expect_uaf': False, 'tarps_expected': 'DEF_FP',
    'code': '''/* TN-05: Branch-Exclusive free/use (SAFE) */
#include <stdlib.h>
#include <string.h>
void branch_exclusive(int mode) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    if (mode == 0) { free(buf); return; }
    else { strcpy(buf, "mode 1"); free(buf); }
}
int main(void) { branch_exclusive(1); return 0; }'''}

SAMPLES['tn_06_different_scope'] = {
    'sample_id': 'TN-06', 'label': 'tn', 'cwe': 'NONE',
    'description': 'Safe: global ptr reassigned to fresh alloc before use',
    'expect_uaf': False, 'tarps_expected': 'DEF_FP',
    'code': '''/* TN-06: Different Scope reassign (SAFE) */
#include <stdlib.h>
static char *g_ptr = NULL;
void init(void) { g_ptr = (char *)malloc(128); }
void cleanup(void) { if (g_ptr) { free(g_ptr); g_ptr = NULL; } }
void use(void) {
    if (!g_ptr) { g_ptr = (char *)malloc(64); }
    if (g_ptr) { g_ptr[0] = 'G'; }
}
int main(void) { init(); cleanup(); use(); free(g_ptr); return 0; }'''}


def main():
    for dirname, info in SAMPLES.items():
        d = os.path.join(BASE, dirname)
        os.makedirs(d, exist_ok=True)
        # sample.c
        with open(os.path.join(d, 'sample.c'), 'w', encoding='utf-8') as f:
            f.write(info['code'])
        # truth.json (exclude 'code' key)
        truth = {k: v for k, v in info.items() if k != 'code'}
        with open(os.path.join(d, 'truth.json'), 'w', encoding='utf-8') as f:
            json.dump(truth, f, indent=2)
        # Makefile
        with open(os.path.join(d, 'Makefile'), 'w') as f:
            f.write("CC=gcc\nCFLAGS=-Wall -O0 -g\nTARGET=sample\n"
                    "all: $(TARGET)\n$(TARGET): sample.c\n"
                    "\t$(CC) $(CFLAGS) -o $(TARGET) sample.c\n"
                    "clean:\n\trm -f $(TARGET)\n")
        # README.md
        with open(os.path.join(d, 'README.md'), 'w', encoding='utf-8') as f:
            f.write(f"# {info['sample_id']}: {info['description']}\n\n"
                    f"- CWE: {info['cwe']}\n"
                    f"- Expected UAF: {info['expect_uaf']}\n"
                    f"- TARPS Expected Verdict: {info['tarps_expected']}\n")
    print(f"Created {len(SAMPLES)} UAF benchmark samples in {BASE}")


if __name__ == '__main__':
    main()
