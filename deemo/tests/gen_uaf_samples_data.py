"""UAF测试C源码样本 — 15个UAF样本的C源码和Makefile模板."""

C_SOURCES = {
    'uaf_simple_double_free': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-01: free后直接使用 — 最简UAF模式 */
int main(int argc, char **argv) {
    char *p = (char *)malloc(128);
    if (!p) return 1;
    strcpy(p, "sensitive_data");
    free(p);
    printf("use after free: %s\n", p);  /* VULNERABLE */
    return 0;
}
''',
    'uaf_alias_ptr': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-02: 别名指针UAF — q=p; free(p); use(q) */
typedef struct { int id; char data[64]; } Record;
int main(void) {
    Record *p = (Record *)malloc(sizeof(Record));
    if (!p) return 1;
    p->id = 42;
    char *q = (char *)p;
    free(p);
    printf("alias access: %s\n", q);  /* VULNERABLE: q是悬挂指针 */
    return 0;
}
''',
    'uaf_loop_free': r'''#include <stdio.h>
#include <stdlib.h>
/* UAF-03: 循环中释放，循环后使用 — 跨基本块生命周期 */
#define N 4
int main(void) {
    char *bufs[N];
    for (int i = 0; i < N; i++) {
        bufs[i] = (char *)malloc(64);
        if (!bufs[i]) return 1;
    }
    for (int i = 0; i < N; i++) free(bufs[i]);
    printf("use after loop: %s\n", bufs[0]);  /* VULNERABLE */
    return 0;
}
''',
    'uaf_cond_free': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-04: 条件释放 — 一条路径free另一条不free, 汇合点use */
int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    strcpy(buf, "conditional_data");
    if (argc > 1) { free(buf); }
    printf("cond use: %s\n", buf);  /* VULNERABLE if argc>1 */
    if (argc <= 1) free(buf);
    return 0;
}
''',
    'uaf_realloc_free': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-05: realloc隐式free — 旧指针自动释放但代码仍持有引用 */
int main(void) {
    char *old = (char *)malloc(32);
    if (!old) return 1;
    strcpy(old, "old_data");
    char *saved = old;
    char *new_ptr = (char *)realloc(old, 128);
    if (!new_ptr) { free(old); return 1; }
    printf("saved ptr: %s\n", saved);  /* VULNERABLE: realloc已释放saved */
    free(new_ptr);
    return 0;
}
''',
    'uaf_struct_field': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-06: 结构体字段指针 — free后通过struct->field访问 */
typedef struct { int size; char *name; char *desc; } Item;
int main(void) {
    Item *it = (Item *)malloc(sizeof(Item));
    if (!it) return 1;
    it->name = (char *)malloc(32);
    strcpy(it->name, "item_name");
    free(it->name);  /* 释放子对象 */
    free(it);        /* 释放父对象 */
    printf("name: %s\n", it->name);  /* VULNERABLE: it和it->name都已释放 */
    return 0;
}
''',
}

MAKEFILE = r'''CC=gcc
CFLAGS=-g -O0 -fno-stack-protector

all: vuln

vuln: vuln.c
	$ $(CFLAGS) -o vuln vuln.c

clean:
	rm -f vuln
'''
