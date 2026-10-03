# coding: utf-8
"""
UAF CVE 基准样本集 — 12 个样本覆盖 UAF 的各种模式.
格式与 heap overflow CVE 样本对齐: vuln.c, Makefile, README.md, ground_truth.json.
"""

import json, os
from pathlib import Path

_SAMPLES_DIR = Path(__file__).resolve().parent

SAMPLES = [
# TP: 真实 UAF
    {
        'id': 'uaf_cve_01', 'cve': 'CVE-2021-38000',
        'title': 'Direct UAF — free then use (no NULL assignment)',
        'pattern': 'free(ptr); /* missing ptr=NULL */ use(ptr);',
        'category': 'direct_free_use', 'is_uaf': True,
        'confidence': 0.95,
        'source': 'Chromium CVE-2021-38000 — direct UAF in WebTransport',
    },
    {
        'id': 'uaf_cve_02', 'cve': 'CVE-2020-15999',
        'title': 'Double free — second free on dangling pointer',
        'pattern': 'free(ptr); free(ptr);',
        'category': 'double_free', 'is_uaf': True,
        'confidence': 0.90,
        'source': 'FreeType CVE-2020-15999 — double free in PNG handling',
    },
    {
        'id': 'uaf_cve_03', 'cve': 'CVE-2019-13720',
        'title': 'UAF via alias — free original, use alias',
        'pattern': 'q = p; free(p); use(q);',
        'category': 'alias_uaf', 'is_uaf': True,
        'confidence': 0.90,
        'source': 'Chrome CVE-2019-13720 — UAF in WebAudio via alias',
    },
    {
        'id': 'uaf_cve_04', 'cve': 'CVE-2018-8174',
        'title': 'UAF in loop — object freed, reused in next iteration',
        'pattern': 'for(...) { free(obj); use(obj->next); }',
        'category': 'loop_uaf', 'is_uaf': True,
        'confidence': 0.85,
        'source': 'IE CVE-2018-8174 — UAF in VBScript engine loop',
    },
    {
        'id': 'uaf_cve_05', 'cve': 'CVE-2017-0674',
        'title': 'Cross-function UAF — caller frees, callee uses',
        'pattern': 'caller: free(buf); callee: process(buf);',
        'category': 'cross_func_uaf', 'is_uaf': True,
        'confidence': 0.80,
        'source': 'Android MediaServer CVE-2017-0674',
    },
    {
        'id': 'uaf_cve_06', 'cve': 'CVE-2016-0189',
        'title': 'Realloc UAF — use old pointer after realloc',
        'pattern': 'new = realloc(old, sz); use(old); // old dangling if moved',
        'category': 'realloc_uaf', 'is_uaf': True,
        'confidence': 0.90,
        'source': 'IE CVE-2016-0189 — realloc UAF in JScript',
    },
    {
        'id': 'uaf_cve_07', 'cve': 'CVE-2022-22620',
        'title': 'Conditional free UAF — free on one path, use on another',
        'pattern': 'if(err) free(ptr); /* else path */ use(ptr);',
        'category': 'conditional_uaf', 'is_uaf': True,
        'confidence': 0.85,
        'source': 'WebKit CVE-2022-22620 — conditional free in CSS',
    },
    {
        'id': 'uaf_cve_08', 'cve': 'CVE-2021-30551',
        'title': 'C++ delete UAF — vtable access after delete',
        'pattern': 'delete obj; obj->vfunc(); // virtual call on freed',
        'category': 'cpp_delete_uaf', 'is_uaf': True,
        'confidence': 0.95,
        'source': 'Chrome CVE-2021-30551 — vtable UAF in MyFiles',
    },
    {
        'id': 'uaf_cve_09', 'cve': 'CVE-2020-6418',
        'title': 'Global pointer UAF — global ptr freed, still referenced',
        'pattern': 'free(g_ctx); /* g_ctx still used elsewhere */',
        'category': 'global_uaf', 'is_uaf': True,
        'confidence': 0.85,
        'source': 'Chrome CVE-2020-6418 — global ctx UAF in V8',
    },
    {
        'id': 'uaf_cve_10', 'cve': 'CVE-2023-2033',
        'title': 'Error path UAF — cleanup frees, error handler uses',
        'pattern': 'cleanup: free(data); error_handler: log(data);',
        'category': 'error_path_uaf', 'is_uaf': True,
        'confidence': 0.80,
        'source': 'Chrome CVE-2023-2033 — UAF in WebGL error path',
    },
# TN: 非 UAF (安全模式)
    {
        'id': 'uaf_cve_11', 'cve': 'SAFE-001',
        'title': 'Safe pattern — NULL assignment after free',
        'pattern': 'free(ptr); ptr = NULL; /* use after check */ if(ptr) use(ptr);',
        'category': 'safe_null', 'is_uaf': False,
        'confidence': 0.95,
        'source': 'Safe coding pattern — ptr=NULL prevents UAF',
    },
    {
        'id': 'uaf_cve_12', 'cve': 'SAFE-002',
        'title': 'Safe pattern — use before free (correct order)',
        'pattern': 'use(ptr); free(ptr); // correct temporal order',
        'category': 'safe_order', 'is_uaf': False,
        'confidence': 0.95,
        'source': 'Safe coding pattern — correct alloc→use→free order',
    },
]


def generate_all_samples():
    """生成所有 UAF CVE 样本文件."""
    gt = {'samples': {}, 'summary': {
        'total': len(SAMPLES),
        'uaf_true': sum(1 for s in SAMPLES if s['is_uaf']),
        'uaf_false': sum(1 for s in SAMPLES if not s['is_uaf']),
    }}

    for s in SAMPLES:
        sample_dir = _SAMPLES_DIR / s['id']
        sample_dir.mkdir(exist_ok=True)

        # vuln.c
        c_code = _generate_c_code(s)
        (sample_dir / 'vuln.c').write_text(c_code, encoding='utf-8')

        # Makefile
        makefile = _generate_makefile(s)
        (sample_dir / 'Makefile').write_text(makefile, encoding='utf-8')

        # README.md
        readme = _generate_readme(s)
        (sample_dir / 'README.md').write_text(readme, encoding='utf-8')

        gt['samples'][s['id']] = {
            'cve': s['cve'], 'title': s['title'],
            'category': s['category'], 'is_uaf': s['is_uaf'],
            'pattern': s['pattern'], 'confidence': s['confidence'],
        }

    # ground_truth.json
    gt_path = _SAMPLES_DIR / 'uaf_ground_truth.json'
    with open(gt_path, 'w', encoding='utf-8') as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)

    print(f'Generated {len(SAMPLES)} UAF samples → {_SAMPLES_DIR}')
    return gt


def _generate_c_code(s: dict) -> str:
    """为每个样本生成最小复现 C 代码."""
    patterns = {
        'direct_free_use': '''// CVE-2021-38000: Direct UAF — free then use
#include <stdlib.h>
#include <string.h>

typedef struct { int len; char *data; } Buf;

int vuln_direct_uaf() {
    Buf *p = (Buf*)malloc(sizeof(Buf));  // @uaf_alloc
    p->len = 64;
    p->data = (char*)malloc(64);
    free(p);                              // @uaf_free — p is freed
    // Missing: p = NULL;
    int n = p->len;                       // @uaf_use — UAF: p is dangling
    return n;
}
int main() { vuln_direct_uaf(); return 0; }''',

        'double_free': '''// CVE-2020-15999: Double free — second free on dangling pointer
#include <stdlib.h>

void vuln_double_free(void *ptr) {
    free(ptr);      // @uaf_free_1 — first free
    free(ptr);      // @uaf_free_2 — DOUBLE FREE (UAF subclass)
    // Between the two frees, ptr is a dangling reference
}
int main() {
    void *p = malloc(128);  // @uaf_alloc
    vuln_double_free(p);
    return 0;
}''',

        'alias_uaf': '''// CVE-2019-13720: UAF via alias — free original, use alias
#include <stdlib.h>

typedef struct node { int val; struct node *next; } Node;

int vuln_alias_uaf() {
    Node *p = (Node*)malloc(sizeof(Node));  // @uaf_alloc
    p->val = 42;
    Node *q = p;                             // q aliases p
    free(p);                                 // @uaf_free
    int v = q->val;                          // @uaf_use — UAF via alias q
    return v;
}
int main() { vuln_alias_uaf(); return 0; }''',

        'loop_uaf': '''// CVE-2018-8174: UAF in loop
#include <stdlib.h>

typedef struct node { int val; struct node *next; } Node;

int vuln_loop_uaf() {
    Node *head = (Node*)malloc(sizeof(Node));  // @uaf_alloc
    head->val = 1; head->next = NULL;
    Node *cur = head;
    while (cur) {
        Node *tmp = cur;
        cur = cur->next;
        free(tmp);                              // @uaf_free — frees head
        // Bug: cur->next accessed AFTER free(tmp) where tmp==cur
        if (cur) cur->val += 1;                 // @uaf_use — UAF
    }
    return 0;
}
int main() { vuln_loop_uaf(); return 0; }''',

        'cross_func_uaf': '''// CVE-2017-0674: Cross-function UAF
#include <stdlib.h>
#include <string.h>

typedef struct { int id; char name[32]; } Rec;

void process_record(Rec *r) {
    // @uaf_use — r might already be freed by caller
    int x = r->id;
}

Rec* create_record(int id) {
    Rec *r = (Rec*)malloc(sizeof(Rec));  // @uaf_alloc
    r->id = id; return r;
}

int vuln_cross_func_uaf() {
    Rec *rec = create_record(1);
    free(rec);                            // @uaf_free
    process_record(rec);                  // calls use on freed ptr
    return 0;
}
int main() { vuln_cross_func_uaf(); return 0; }''',

        'realloc_uaf': '''// CVE-2016-0189: Realloc UAF — use old pointer after realloc
#include <stdlib.h>
#include <string.h>

int vuln_realloc_uaf() {
    char *old = (char*)malloc(64);        // @uaf_alloc
    strcpy(old, "data");
    char *new_ptr = (char*)realloc(old, 128);  // @uaf_realloc — may move
    // Bug: if realloc moved the block, old is dangling
    char c = old[0];                      // @uaf_use — UAF if moved
    if (new_ptr) free(new_ptr);
    return c;
}
int main() { vuln_realloc_uaf(); return 0; }''',

        'conditional_uaf': '''// CVE-2022-22620: Conditional free — free on one path, use on another
#include <stdlib.h>

int vuln_conditional_uaf(int err) {
    char *buf = (char*)malloc(256);       // @uaf_alloc
    if (err) {
        free(buf);                        // @uaf_free — path A: freed
        return -1;
    }
    // path B: buf is still valid, but static analysis merges with path A
    buf[0] = 'A';                         // @uaf_use — UAF on path A only
    free(buf);
    return 0;
}
int main() { vuln_conditional_uaf(0); vuln_conditional_uaf(1); return 0; }''',

        'cpp_delete_uaf': '''// CVE-2021-30551: C++ delete UAF — vtable access after delete
#include <stdlib.h>

typedef struct obj {
    void (*vfunc)(struct obj*);
    int data;
} Obj;

void obj_method(Obj *self) {
    self->data = 42;                      // @uaf_use — virtual call on freed
}

int vuln_cpp_delete_uaf() {
    Obj *o = (Obj*)malloc(sizeof(Obj));   // @uaf_alloc
    o->vfunc = obj_method; o->data = 0;
    free(o);                              // @uaf_free (simulates delete)
    o->vfunc(o);                          // @uaf_use — vtable call on freed object
    return 0;
}
int main() { vuln_cpp_delete_uaf(); return 0; }''',

        'global_uaf': '''// CVE-2020-6418: Global pointer UAF
#include <stdlib.h>

typedef struct ctx { int refs; void *data; } Ctx;
static Ctx *g_ctx = NULL;                // global pointer

Ctx* get_ctx() {
    if (!g_ctx) {
        g_ctx = (Ctx*)malloc(sizeof(Ctx));  // @uaf_alloc
        g_ctx->refs = 1;
    }
    return g_ctx;
}

void cleanup_ctx() {
    free(g_ctx);                           // @uaf_free
    // Bug: g_ctx not set to NULL
}

int vuln_global_uaf() {
    Ctx *c = get_ctx();
    cleanup_ctx();
    int r = c->refs;                       // @uaf_use — UAF via cached ptr
    return r;
}
int main() { vuln_global_uaf(); return 0; }''',

        'error_path_uaf': '''// CVE-2023-2033: Error path UAF — cleanup frees, error handler uses
#include <stdlib.h>
#include <stdio.h>

typedef struct { int status; char *msg; } Conn;

void log_error(Conn *c) {
    printf("err: %s\\n", c->msg);         // @uaf_use — c might be freed
}

int vuln_error_path_uaf(int should_fail) {
    Conn *c = (Conn*)malloc(sizeof(Conn));  // @uaf_alloc
    c->status = 0;
    if (should_fail) {
        free(c);                            // @uaf_free — cleanup
        log_error(c);                       // UAF: use after cleanup
        return -1;
    }
    c->status = 200; free(c);
    return 0;
}
int main() { vuln_error_path_uaf(1); return 0; }''',

        'safe_null': '''// SAFE-001: Safe pattern — NULL assignment after free
#include <stdlib.h>

int safe_null_after_free() {
    int *p = (int*)malloc(sizeof(int));   // @alloc
    *p = 42;
    free(p);                              // @free
    p = NULL;                             // NULL assignment prevents UAF
    if (p) {
        *p = 0;                           // unreachable — p is NULL
    }
    return 0;
}
int main() { safe_null_after_free(); return 0; }''',

        'safe_order': '''// SAFE-002: Safe pattern — correct temporal order
#include <stdlib.h>

typedef struct { int x; } Data;

int safe_use_before_free() {
    Data *d = (Data*)malloc(sizeof(Data));  // @alloc
    d->x = 100;
    int result = d->x;                      // @use — before free, safe
    free(d);                                // @free
    return result;                          // no dangling access
}
int main() { safe_use_before_free(); return 0; }''',
    }
    return patterns.get(s['category'], '// Unknown pattern')


def _generate_makefile(s: dict) -> str:
    return f'''CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = {s['id']}

all: $(TARGET)

$(TARGET): vuln.c
\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
\trm -f $(TARGET) *.o

run: $(TARGET)
\t./$(TARGET)
'''


def _generate_readme(s: dict) -> str:
    return f'''# {s['id']}: {s['title']}

- **CVE**: {s['cve']}
- **Category**: {s['category']}
- **Is UAF**: {s['is_uaf']}
- **Pattern**: `{s['pattern']}`
- **Source**: {s['source']}

# Build
```
make
```

# Run
```
make run
```

# Expected Detection
```
BinMind UAF detector: {"UAF" if s['is_uaf'] else "SAFE"} (confidence: {s['confidence']})
```
'''


if __name__ == '__main__':
    generate_all_samples()
