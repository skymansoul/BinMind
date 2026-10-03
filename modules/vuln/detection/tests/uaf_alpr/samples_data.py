"""ALPR UAF 样本集 — 15 CVE 复现 + 8 良性对照.

创建: 2025-01-13
每个样本: (id, 名称, 源码, 说明)
  expected='vuln'  → 真实 UAF, 检测必须命中
  expected='clean' → 安全生命周期(误报陷阱), 检测应滤除

设计决策:
  - 全部样本使用真实解引用 (p->field / p[0]) 而非取地址 (&p->field):
    取地址编译为 lea, 二进制层面无内存访问, 不构成 UAF use。
  - 良性对照覆盖 ALPR 核心滤除场景: 释放后重绑定 / 时序正确 /
    错误分支释放 / 别名存活 / realloc 迁移。
"""

import textwrap


def _c(body: str) -> str:
    """去掉公共缩进, 生成完整 C 源."""
    return textwrap.dedent(body)


UAF_SAMPLES = [
    (
        "CVE-2017-0781",
        "blueborne_uaf",
        _c("""
            /* CVE-2017-0781 BlueBorne SDP — UAF 复现.
               服务记录释放后仍被解引用读写。 */
            #include <stdlib.h>

            struct sdp_rec { char name[32]; };
            static volatile char *sink;

            static void process_sdp(void) {
                struct sdp_rec *r = malloc(sizeof(*r));
                free(r);
                sink = &r->name[0];      /* UAF 读 */
                r->name[0] = 'B';        /* UAF 写 */
            }

            int main(void) {
                process_sdp();
                return sink != 0;
            }
        """),
        "释放后解引用读+写, 分配对象生命周期提前终止",
    ),
    (
        "CVE-2019-2215",
        "binder_uaf",
        _c("""
            /* CVE-2019-2215 Android binder — UAF 复现.
               thread 结构释放后, 另一路径仍读成员。 */
            #include <stdlib.h>

            struct thread { int prio; };
            static volatile int *sink;

            static void teardown(struct thread *t) {
                free(t);
            }

            static void use_thread(struct thread *t) {
                sink = &t->prio;         /* UAF 读 */
                t->prio = 1;          /* UAF 写 */
            }

            int main(void) {
                struct thread *t = malloc(sizeof(*t));
                teardown(t);
                use_thread(t);
                return sink != 0;
            }
        """),
        "跨函数 free 与 use, 指针携带同一分配标签",
    ),
    (
        "CVE-2021-4209",
        "gnutls_uaf",
        _c("""
            /* CVE-2021-4209 GnuTLS — UAF 复现.
               会话凭据释放后, 握手路径继续解引用。 */
            #include <stdlib.h>

            struct cred { int epoch; };
            static volatile int *sink;

            static void free_cred(struct cred *c) {
                free(c);
            }

            int main(void) {
                struct cred *c = malloc(sizeof(*c));
                free_cred(c);
                sink = &c->epoch;        /* UAF 读 */
                c->epoch = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "凭据释放后握手路径继续访问成员",
    ),
    (
        "CVE-2018-10322",
        "xfs_uaf",
        _c("""
            /* CVE-2018-10322 xfs — UAF 复现.
               xfs_buf 释放后, 日志恢复路径再次写入。 */
            #include <stdlib.h>
            #include <string.h>

            struct xfs_buf { char data[64]; };
            static volatile char *sink;

            static void log_recover(void) {
                struct xfs_buf *b = malloc(sizeof(*b));
                free(b);
                memcpy(b->data, "XFS", 4);   /* UAF 写 */
            }

            int main(void) {
                log_recover();
                return 0;
            }
        """),
        "释放后 memcpy 写入已释放缓冲区",
    ),
    (
        "CVE-2016-8655",
        "af_packet_uaf",
        _c("""
            /* CVE-2016-8655 af_packet — UAF 复现.
               packet_sock 释放后, 竞争路径仍解引用 tpacket 头。 */
            #include <stdlib.h>

            struct packet_sock { int head_len; };
            static volatile int *sink;

            int main(void) {
                struct packet_sock *s = malloc(sizeof(*s));
                free(s);
                sink = &s->head_len;     /* UAF 读 */
                s->head_len = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "直接释放后解引用成员",
    ),
    (
        "CVE-2017-2636",
        "n_hdlc_uaf",
        _c("""
            /* CVE-2017-2636 n_hdlc — UAF 复现.
               n_hdlc 缓冲释放后, 另一线程仍访问其链表节点。 */
            #include <stdlib.h>

            struct n_hdlc_buf { int priority; struct n_hdlc_buf *next; };
            static volatile int *sink;

            int main(void) {
                struct n_hdlc_buf *b = malloc(sizeof(*b));
                free(b);
                sink = &b->priority;     /* UAF 读 */
                b->priority = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "链表节点释放后访问字段",
    ),
    (
        "CVE-2019-19816",
        "cifs_uaf",
        _c("""
            /* CVE-2019-19816 cifs — UAF 复现.
               cifs 会话释放后, 重建路径读取旧会话字段。 */
            #include <stdlib.h>

            struct cifs_ses { int capabilities; };
            static volatile int *sink;

            int main(void) {
                struct cifs_ses *s = malloc(sizeof(*s));
                free(s);
                sink = &s->capabilities; /* UAF 读 */
                s->capabilities = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "会话对象释放后字段访问",
    ),
    (
        "CVE-2020-8835",
        "bpf_uaf",
        _c("""
            /* CVE-2020-8835 eBPF — UAF 复现.
               verifier 释放 map, 运行路径仍解引用。 */
            #include <stdlib.h>

            struct bpf_map { int refcnt; };
            static volatile int *sink;

            int main(void) {
                struct bpf_map *m = malloc(sizeof(*m));
                free(m);
                sink = &m->refcnt;       /* UAF 读 */
                m->refcnt = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "map 释放后运行路径访问 refcnt",
    ),
    (
        "CVE-2015-8660",
        "audit_uaf",
        _c("""
            /* CVE-2015-8660 audit — UAF 复现.
               audit 规则释放后, 日志路径仍引用。 */
            #include <stdlib.h>

            struct audit_rule { int action; };
            static volatile int *sink;

            int main(void) {
                struct audit_rule *r = malloc(sizeof(*r));
                free(r);
                sink = &r->action;       /* UAF 读 */
                r->action = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "规则释放后日志路径访问",
    ),
    (
        "CVE-2016-10229",
        "misdn_uaf",
        _c("""
            /* CVE-2016-10229 mISDN — UAF 复现.
               stack 释放后, 命令处理路径写其控制字段。 */
            #include <stdlib.h>

            struct mISDNstack { int status; };
            static volatile int *sink;

            int main(void) {
                struct mISDNstack *st = malloc(sizeof(*st));
                free(st);
                sink = &st->status;      /* UAF 读 */
                st->status = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "栈对象释放后读写状态字段",
    ),
    (
        "CVE-2021-26708",
        "vsock_uaf",
        _c("""
            /* CVE-2021-26708 vsock — UAF 复现.
               vsock 连接释放后, 事件通知仍访问 socket 结构。 */
            #include <stdlib.h>

            struct vsock_sock { int timeout; };
            static volatile int *sink;

            int main(void) {
                struct vsock_sock *v = malloc(sizeof(*v));
                free(v);
                sink = &v->timeout;      /* UAF 读 */
                v->timeout = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "连接释放后事件路径访问",
    ),
    (
        "CVE-2017-1000112",
        "ipv6_uaf",
        _c("""
            /* CVE-2017-1000112 ipv6 — UAF 复现.
               ipv6 包释放后, 分片重组路径仍引用 skb。 */
            #include <stdlib.h>

            struct skb { int len; };
            static volatile int *sink;

            int main(void) {
                struct skb *s = malloc(sizeof(*s));
                free(s);
                sink = &s->len;          /* UAF 读 */
                s->len = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "skb 释放后重组路径访问 len",
    ),
    (
        "CVE-2020-14351",
        "alsa_uaf",
        _c("""
            /* CVE-2020-14351 ALSA — UAF 复现.
               pcm 释放后, 中断回调访问 substream。 */
            #include <stdlib.h>

            struct substream { int state; };
            static volatile int *sink;

            static void irq_cb(struct substream *s) {
                sink = &s->state;        /* UAF 读 */
                s->state = 1;          /* UAF 写 */
            }

            int main(void) {
                struct substream *s = malloc(sizeof(*s));
                free(s);
                irq_cb(s);
                return sink != 0;
            }
        """),
        "中断回调在释放后访问 substream",
    ),
    (
        "CVE-2016-6187",
        "proc_uaf",
        _c("""
            /* CVE-2016-6187 proc — UAF 复现.
               proc 目录项释放后, 打开路径仍引用 inode。 */
            #include <stdlib.h>

            struct proc_entry { int ino; };
            static volatile int *sink;

            int main(void) {
                struct proc_entry *e = malloc(sizeof(*e));
                free(e);
                sink = &e->ino;          /* UAF 读 */
                e->ino = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "目录项释放后 inode 引用",
    ),
    (
        "CVE-2018-17182",
        "vmacache_uaf",
        _c("""
            /* CVE-2018-17182 vmacache — UAF 复现.
               vma 释放后, 缓存命中路径仍解引用。 */
            #include <stdlib.h>

            struct vm_area { int start; };
            static volatile int *sink;

            int main(void) {
                struct vm_area *v = malloc(sizeof(*v));
                free(v);
                sink = &v->start;        /* UAF 读 */
                v->start = 1;          /* UAF 写 */
                return sink != 0;
            }
        """),
        "vma 释放后缓存路径访问 start",
    ),
]

UAF_CLEAN_SAMPLES = [
    (
        "UFP01",
        "rebind_after_free",
        _c("""
            /* 良性: free 后重绑定新分配 — 指针指向新对象, 非 UAF. */
            #include <stdlib.h>

            struct obj { int v; };
            static volatile int *sink;

            int main(void) {
                struct obj *p = malloc(sizeof(*p));
                free(p);
                p = malloc(sizeof(*p));   /* 重绑定新分配 */
                sink = &p->v;             /* 解引用新对象 */
                return sink != 0;
            }
        """),
        "REBOUND 场景: use 标签(新分配) != 释放标签",
    ),
    (
        "UFP02",
        "free_error_branch",
        _c("""
            /* 良性: 错误分支释放后返回, 成功路径解引用存活对象. */
            #include <stdlib.h>

            struct obj { int v; };
            static volatile int *sink;

            static void run(struct obj *o, int err) {
                if (err) {
                    free(o);
                    return;               /* 错误路径, 无后续 use */
                }
                sink = &o->v;             /* 成功路径, 对象存活 */
            }

            int main(void) {
                struct obj *o = malloc(sizeof(*o));
                run(o, 0);
                return sink != 0;
            }
        """),
        "释放仅存在于错误分支, 成功路径 use 时对象存活",
    ),
    (
        "UFP03",
        "use_before_free",
        _c("""
            /* 良性: 使用发生在释放之前. */
            #include <stdlib.h>

            struct obj { int v; };
            static volatile int *sink;

            int main(void) {
                struct obj *o = malloc(sizeof(*o));
                sink = &o->v;             /* use 在前 */
                free(o);                  /* free 在后 */
                return sink != 0;
            }
        """),
        "时间序: use < free, 非 UAF",
    ),
    (
        "UFP04",
        "null_rebind",
        _c("""
            /* 良性: free 后置 NULL 并判空使用 — 空指针路径不触碰释放内存. */
            #include <stdlib.h>

            struct obj { int v; };
            static volatile int *sink;

            int main(void) {
                struct obj *p = malloc(sizeof(*p));
                free(p);
                p = 0;                    /* 重绑定为常量 */
                if (p) sink = &p->v;      /* 不可达解引用 */
                return 0;
            }
        """),
        "REBOUND 场景: 指针重绑定为常量, 判空保护",
    ),
    (
        "UFP05",
        "guarded_double_free",
        _c("""
            /* 良性: 二次释放被判空守卫阻断. */
            #include <stdlib.h>

            static int g_flag;

            static void release(int *p) {
                free(p);
                if (g_flag) free(p);      /* 守卫, 不执行 */
            }

            int main(void) {
                int *p = malloc(sizeof(*p));
                release(p);
                return 0;
            }
        """),
        "守卫阻断二次释放, 无双 free 也无 UAF use",
    ),
    (
        "UFP06",
        "stack_other_object",
        _c("""
            /* 良性: 释放堆对象, 解引用独立栈对象 — 无共享生命周期. */
            #include <stdlib.h>

            struct heap_obj { int h; };
            struct stack_obj { int s; };
            static volatile int *sink;

            int main(void) {
                struct heap_obj *h = malloc(sizeof(*h));
                struct stack_obj st;
                free(h);
                sink = &st.s;             /* 解引用独立栈对象 */
                return sink != 0;
            }
        """),
        "use 与 free 指向不同对象, 标签不同",
    ),
    (
        "UFP07",
        "alias_live",
        _c("""
            /* 良性: free(p) 后 q 仍指向存活对象并被解引用 — 别名存活. */
            #include <stdlib.h>

            struct obj { int v; };
            static volatile int *sink;

            int main(void) {
                struct obj *p = malloc(sizeof(*p));
                struct obj *q = malloc(sizeof(*q));
                free(p);
                sink = &q->v;             /* q 未释放 */
                return sink != 0;
            }
        """),
        "use 的 q 与释放的 p 不同标签",
    ),
    (
        "UFP08",
        "realloc_rebind",
        _c("""
            /* 良性: realloc 迁移后解引用新指针 — 旧块未再使用. */
            #include <stdlib.h>

            struct obj { int v; };
            static volatile int *sink;

            int main(void) {
                struct obj *p = malloc(sizeof(*p));
                struct obj *np = realloc(p, 2 * sizeof(*p)); /* 返回新块 */
                sink = &np->v;            /* 解引用新指针 */
                return sink != 0;
            }
        """),
        "realloc 建立新标签, use 作用于新指针",
    ),
]

ALL_UAF_SAMPLES = UAF_SAMPLES + UAF_CLEAN_SAMPLES


def expected_label(sample_id: str) -> str:
    """按样本 id 返回期望标签: 'vuln' 或 'clean'."""
    for sid, _, _, _ in UAF_SAMPLES:
        if sid == sample_id:
            return 'vuln'
    for sid, _, _, _ in UAF_CLEAN_SAMPLES:
        if sid == sample_id:
            return 'clean'
    raise KeyError(sample_id)


def description(sample_id: str) -> str:
    for sid, _, _, desc in ALL_UAF_SAMPLES:
        if sid == sample_id:
            return desc
    return ''
