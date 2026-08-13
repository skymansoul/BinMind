"""UAF 安全(误报基准)样本定义 — 朴素基线报但实际安全。

每个陷阱对应一个 LCV 安全信号:
  FP-01 重绑定      → 对象流 (p 指向新对象)
  FP-02 空化+守卫   → 对象流 (p 指向空)
  FP-03 分支互斥    → branch_exclusive
  FP-04 字段区分    → 对象键 (不同子对象)
  FP-05 对象不同    → 对象键
  FP-06 realloc 重生 → 对象流
  FP-07 互斥释放/使用 → branch_exclusive
  FP-08 空化后守卫   → 对象流
"""

import textwrap

SAMPLE_DEFS_SAFE = [

    # FP-01 释放后重分配
    {
        'name': 'UAF-FP-01_reborn',
        'cve': '',
        'category': 'uaf_safe',
        'func': 'safe_reborn',
        'truth': {'is_vuln': False, 'pattern': 'reborn',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'reborn'},
        'readme': 'free(p) 后重新 malloc, p 指向新对象 — 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_reborn(int v)
            {
                char *p = (char *)malloc(16);
                if (!p)
                    return;
                free(p);
                p = (char *)malloc(16);
                if (!p)
                    return;
                p[0] = (char)v;
                free(p);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_reborn(atoi(argv[1]));
                return 0;
            }
        '''),
    },

    # FP-02 空化 + 守卫
    {
        'name': 'UAF-FP-02_null_guard',
        'cve': '',
        'category': 'uaf_safe',
        'func': 'safe_null_guard',
        'truth': {'is_vuln': False, 'pattern': 'null_guard',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'nulled'},
        'readme': 'free 后 p 置空, use 受 if(p) 守卫 — 永不解引用悬垂指针。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_null_guard(void)
            {
                char *p = (char *)malloc(16);
                if (!p)
                    return;
                free(p);
                p = 0;
                if (p)
                    p[0] = 1;
            }

            int main(void)
            {
                safe_null_guard();
                return 0;
            }
        '''),
    },

    # FP-03 分支互斥
    {
        'name': 'UAF-FP-03_branch_exclusive',
        'cve': '',
        'category': 'uaf_safe',
        'func': 'safe_branch_exclusive',
        'truth': {'is_vuln': False, 'pattern': 'branch_exclusive',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'exclusive'},
        'readme': 'if 对立分支分别释放与使用 — 永不共存。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_branch_exclusive(int flag)
            {
                char *p = (char *)malloc(16);
                if (!p)
                    return;
                if (flag) {
                    free(p);
                } else {
                    p[0] = 1;
                    free(p);
                }
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_branch_exclusive(atoi(argv[1]));
                return 0;
            }
        '''),
    },

    # FP-04 字段区分
    {
        'name': 'UAF-FP-04_field_distinct',
        'cve': '',
        'category': 'uaf_safe',
        'func': 'safe_field_distinct',
        'truth': {'is_vuln': False, 'pattern': 'field_distinct',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'objkey'},
        'readme': 'free(b->buf) 只释放子缓冲, b 本身存活, 写 b->len 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct item {
                char *buf;
                int len;
            };

            static void safe_field_distinct(void)
            {
                struct item *b = (struct item *)malloc(sizeof(struct item));
                if (!b)
                    return;
                b->buf = (char *)malloc(32);
                free(b->buf);
                b->len = 5;
                free(b);
            }

            int main(void)
            {
                safe_field_distinct();
                return 0;
            }
        '''),
    },

    # FP-05 对象不同
    {
        'name': 'UAF-FP-05_distinct_objects',
        'cve': '',
        'category': 'uaf_safe',
        'func': 'safe_distinct',
        'truth': {'is_vuln': False, 'pattern': 'distinct_objects',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'objkey'},
        'readme': '释放 p 使用 q, 两个独立分配对象 — 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_distinct(void)
            {
                char *p = (char *)malloc(16);
                char *q = (char *)malloc(16);
                if (!p || !q)
                    return;
                free(p);
                q[0] = 1;
                free(q);
            }

            int main(void)
            {
                safe_distinct();
                return 0;
            }
        '''),
    },

    # FP-06 realloc 重生
    {
        'name': 'UAF-FP-06_realloc_reborn',
        'cve': '',
        'category': 'uaf_safe',
        'func': 'safe_realloc_reborn',
        'truth': {'is_vuln': False, 'pattern': 'realloc_reborn',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'reborn'},
        'readme': 'free 后经 realloc 获得新对象, 使用安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_realloc_reborn(int n)
            {
                char *p = (char *)malloc(16);
                if (!p)
                    return;
                free(p);
                p = (char *)realloc(0, (size_t)n);
                if (!p)
                    return;
                p[0] = 1;
                free(p);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_realloc_reborn(atoi(argv[1]));
                return 0;
            }
        '''),
    },

    # FP-07 互斥释放/使用
    {
        'name': 'UAF-FP-07_exclusive_free_use',
        'cve': '',
        'category': 'uaf_safe',
        'func': 'safe_exclusive',
        'truth': {'is_vuln': False, 'pattern': 'exclusive_free_use',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'exclusive'},
        'readme': '引用计数守卫: 计数器降零才释放, 否则分支使用 — 互斥。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_exclusive(int ref)
            {
                char *p = (char *)malloc(16);
                if (!p)
                    return;
                if (ref == 0) {
                    free(p);
                } else {
                    p[0] = 1;
                    free(p);
                }
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                safe_exclusive(atoi(argv[1]));
                return 0;
            }
        '''),
    },

    # FP-08 空化 + while 守卫
    {
        'name': 'UAF-FP-08_null_loop_guard',
        'cve': '',
        'category': 'uaf_safe',
        'func': 'safe_null_loop',
        'truth': {'is_vuln': False, 'pattern': 'null_loop_guard',
                  'overflow_kind': 'none', 'cwe': '', 'filter': 'nulled'},
        'readme': 'free 后置空, while(p) 守卫内的使用永不执行 — 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_null_loop(void)
            {
                char *p = (char *)malloc(16);
                if (!p)
                    return;
                free(p);
                p = 0;
                while (p)
                    p[0] = 1;
            }

            int main(void)
            {
                safe_null_loop();
                return 0;
            }
        '''),
    },
]
