"""???? ? ?????????(????)?
????: ???? + main ??; ???????? CVE ??,
??????????
"""

import textwrap


SAMPLE_DEFS_SAFE_B = [
    {
        'name': 'FP-05_strcpy_literal',
        'cve': '',
        'category': 'safe',
        'func': 'safe_strcpy',
        'truth': {
            'is_vuln': False, 'pattern': 'strcpy_literal',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'string-literal-len',
        },
        'readme': 'strcpy 到 malloc(64), 源为已知字面量 — 长度可证。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            static void safe_strcpy(void)
            {
                char *buf = (char *)malloc(64);
                if (!buf)
                    return;
                strcpy(buf, "hello world");
                free(buf);
            }

            int main(void)
            {
                safe_strcpy();
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-06_realloc_expansion',
        'cve': '',
        'category': 'safe',
        'func': 'safe_realloc',
        'truth': {
            'is_vuln': False, 'pattern': 'realloc_expand',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'alloc-dedup',
        },
        'readme': 'malloc(16) 后 realloc(16*4), 循环写 int 数组 — 扩容后安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_realloc(void)
            {
                int *buf = (int *)malloc(16);
                if (!buf)
                    return;
                buf = (int *)realloc(buf, 16 * 4);
                if (!buf)
                    return;
                int i;
                for (i = 0; i < 16; i++) {
                    buf[i] = i;
                }
                free(buf);
            }

            int main(void)
            {
                safe_realloc();
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-07_struct_fields',
        'cve': '',
        'category': 'safe',
        'func': 'safe_struct',
        'truth': {
            'is_vuln': False, 'pattern': 'struct_fields',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'struct-layout',
        },
        'readme': 'malloc(sizeof(struct)) 后逐字段写 — 布局内合法访问。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            struct Node {
                int a;
                int b;
                int c;
            };

            static void safe_struct(void)
            {
                struct Node *n = (struct Node *)malloc(sizeof(struct Node));
                if (!n)
                    return;
                n->a = 1;
                n->b = 2;
                n->c = 3;
                free(n);
            }

            int main(void)
            {
                safe_struct();
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-08_strncpy_terminated',
        'cve': '',
        'category': 'safe',
        'func': 'safe_strncpy',
        'truth': {
            'is_vuln': False, 'pattern': 'strncpy_terminated',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'interval',
        },
        'readme': 'strncpy n-1 字节后手动补 0 — 总量恰为 n 不越界。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            static void safe_strncpy(const char *src, size_t n)
            {
                if (n > 64)
                    return;
                char *buf = (char *)malloc(64);
                if (!buf)
                    return;
                strncpy(buf, src, n - 1);
                buf[n - 1] = '\\0';
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                safe_strncpy(argv[2], n);
                return 0;
            }
        '''),
    },
]
