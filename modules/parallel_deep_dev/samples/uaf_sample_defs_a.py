"""UAF 样本定义 (CVE 1-8) — 生成样本集的源数据。

每个样本: 触发函数(分配→释放→使用) + main 驱动。漏洞模式复刻
对应 CVE 的 use-after-free 根因(释放后解引用/别名穿透/字段释放/
重复释放), 以最小可编译 C 复现其生命周期违约语义。
"""

import textwrap

SAMPLE_DEFS_A = [

    # 1. CVE-2017-11176: 释放后直接解引用
    {
        'name': 'CVE-2017-11176_netlink',
        'cve': 'CVE-2017-11176',
        'category': 'uaf',
        'func': 'netlink_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_deref',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Linux netlink 引用计数缺陷导致 sock 对象被释放后仍被\n'
                  '访问。复现: free(o) 后写 o->data。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            struct nlobj {
                int ref;
                void *data;
            };

            static void netlink_trigger(int n)
            {
                struct nlobj *o = (struct nlobj *)malloc(sizeof(struct nlobj));
                if (!o)
                    return;
                free(o);
                o->data = (void *)(long)n;
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                netlink_trigger(atoi(argv[1]));
                return 0;
            }
        '''),
    },

    # 2. CVE-2018-9568: 释放后读取字段
    {
        'name': 'CVE-2018-9568_binder',
        'cve': 'CVE-2018-9568',
        'category': 'uaf',
        'func': 'binder_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_read',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Android binder 事务处理中的 use-after-free: 节点释放后\n'
                  '仍被读取。复现: free(n) 后读 n->cookie。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct binder_node {
                int cookie;
            };

            static void binder_trigger(void)
            {
                struct binder_node *n =
                    (struct binder_node *)malloc(sizeof(struct binder_node));
                if (!n)
                    return;
                n->cookie = 7;
                free(n);
                printf("%d\\n", n->cookie);
            }

            int main(void)
            {
                binder_trigger();
                return 0;
            }
        '''),
    },

    # 3. CVE-2019-2215: 释放后经 ioctl 使用
    {
        'name': 'CVE-2019-2215_binder',
        'cve': 'CVE-2019-2215',
        'category': 'uaf',
        'func': 'binder_ioctl_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_use',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Android binder use-after-free: 对象经 fd 引用在释放后\n'
                  '仍可达。复现: free(p) 后写 *p。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void binder_ioctl_trigger(void)
            {
                int *p = (int *)malloc(sizeof(int));
                if (!p)
                    return;
                *p = 1;
                free(p);
                *p = 2;
            }

            int main(void)
            {
                binder_ioctl_trigger();
                return 0;
            }
        '''),
    },

    # 4. CVE-2018-17182: 释放后在循环中解引用
    {
        'name': 'CVE-2018-17182_vmacache',
        'cve': 'CVE-2018-17182',
        'category': 'uaf',
        'func': 'vmac_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_loop_deref',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Linux vmacache 页表遍历中的 use-after-free。复现:\n'
                  'free(v) 后循环写 v->area[i]。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct vma {
                int area[4];
            };

            static void vmac_trigger(void)
            {
                struct vma *v = (struct vma *)malloc(sizeof(struct vma));
                int i;
                if (!v)
                    return;
                free(v);
                for (i = 0; i < 4; i++)
                    v->area[i] = i;
            }

            int main(void)
            {
                vmac_trigger();
                return 0;
            }
        '''),
    },

    # 5. CVE-2020-14356: 重复释放
    {
        'name': 'CVE-2020-14356_netfilter',
        'cve': 'CVE-2020-14356',
        'category': 'uaf',
        'func': 'nft_trigger',
        'truth': {'is_vuln': True, 'pattern': 'double_free',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-415'},
        'readme': 'Linux nf_tables 表项释放路径竞争导致 double-free。\n'
                  '复现: free(e) 两次。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void nft_trigger(void)
            {
                char *e = (char *)malloc(32);
                if (!e)
                    return;
                free(e);
                free(e);
            }

            int main(void)
            {
                nft_trigger();
                return 0;
            }
        '''),
    },

    # 6. CVE-2020-10711: 释放后传参
    {
        'name': 'CVE-2020-10711_netfilter',
        'cve': 'CVE-2020-10711',
        'category': 'uaf',
        'func': 'nfset_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_callarg',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Linux nf_tables set 元素 use-after-free: 释放后\n'
                  '仍传入处理函数。复现: free(s) 后 process(s)。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void process(char *s)
            {
                s[0] = 'x';
            }

            static void nfset_trigger(void)
            {
                char *s = (char *)malloc(16);
                if (!s)
                    return;
                free(s);
                process(s);
            }

            int main(void)
            {
                nfset_trigger();
                return 0;
            }
        '''),
    },

    # 7. CVE-2021-0920: 别名穿透
    {
        'name': 'CVE-2021-0920_kgsl',
        'cve': 'CVE-2021-0920',
        'category': 'uaf',
        'func': 'kgsl_trigger',
        'truth': {'is_vuln': True, 'pattern': 'alias_uaf',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Adreno kgsl 设备释放后经别名指针仍可达。复现:\n'
                  'q=p 建立别名, free(p) 后经 q 写字段。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct kgsl_obj {
                int id;
            };

            static void kgsl_trigger(void)
            {
                struct kgsl_obj *p =
                    (struct kgsl_obj *)malloc(sizeof(struct kgsl_obj));
                struct kgsl_obj *q = p;
                if (!p)
                    return;
                free(p);
                q->id = 42;
            }

            int main(void)
            {
                kgsl_trigger();
                return 0;
            }
        '''),
    },

    # 8. CVE-2021-1905: 释放后写目标字段
    {
        'name': 'CVE-2021-1905_kgsl',
        'cve': 'CVE-2021-1905',
        'category': 'uaf',
        'func': 'kgsl_write_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_write',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Adreno kgsl ioctl 中对象释放后写其字段。复现:\n'
                  'free(e) 后写 e->size。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct kgsl_entry {
                unsigned size;
            };

            static void kgsl_write_trigger(unsigned sz)
            {
                struct kgsl_entry *e =
                    (struct kgsl_entry *)malloc(sizeof(struct kgsl_entry));
                if (!e)
                    return;
                free(e);
                e->size = sz;
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                kgsl_write_trigger((unsigned)atoi(argv[1]));
                return 0;
            }
        '''),
    },
]
