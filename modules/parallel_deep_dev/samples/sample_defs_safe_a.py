"""???? ? ?????????(????)?
????: ???? + main ??; ???????? CVE ??,
??????????
"""

import textwrap


SAMPLE_DEFS_SAFE_A = [
    {
        'name': 'FP-01_coupled_len',
        'cve': '',
        'category': 'safe',
        'func': 'safe_copy',
        'truth': {
            'is_vuln': False, 'pattern': 'coupled_len',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'coupled-delta',
        },
        'readme': 'malloc(n) 后 memcpy 恰好 n 字节 — 安全等长复制。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            static void safe_copy(const char *input, size_t n)
            {
                char *buf = (char *)malloc(n);
                if (!buf)
                    return;
                memcpy(buf, input, n);
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                safe_copy(argv[2], n);
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-02_loop_scaled',
        'cve': '',
        'category': 'safe',
        'func': 'safe_loop',
        'truth': {
            'is_vuln': False, 'pattern': 'loop_scaled',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'guard-subst',
        },
        'readme': 'malloc(n*4) 且循环 i<n 写 int 数组 — 容量恰配。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_loop(size_t n)
            {
                int *buf = (int *)malloc(n * 4);
                if (!buf)
                    return;
                size_t i;
                for (i = 0; i < n; i++) {
                    buf[i] = (int)i;
                }
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                size_t n = (size_t)strtoul(argv[1], NULL, 10);
                safe_loop(n);
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-03_guard_check',
        'cve': '',
        'category': 'safe',
        'func': 'safe_guarded',
        'truth': {
            'is_vuln': False, 'pattern': 'guard_check',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'guard-subst',
        },
        'readme': 'if (len > size) return; 后再 memcpy — 守卫保护。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            static void safe_guarded(const char *input, size_t len, size_t size)
            {
                char *buf = (char *)malloc(size);
                if (!buf)
                    return;
                if (len > size)
                    return;
                memcpy(buf, input, len);
                free(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 4)
                    return 1;
                size_t len = (size_t)strtoul(argv[1], NULL, 10);
                size_t size = (size_t)strtoul(argv[2], NULL, 10);
                safe_guarded(argv[3], len, size);
                return 0;
            }
        '''),
    },

    {
        'name': 'FP-04_aligned_slack',
        'cve': '',
        'category': 'safe',
        'func': 'safe_aligned',
        'truth': {
            'is_vuln': False, 'pattern': 'aligned_slack',
            'overflow_kind': 'none', 'cwe': '',
            'filter': 'aligned-capacity',
        },
        'readme': 'malloc(17) 的 chunk 对齐到 32 字节, 写 24..31 安全。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void safe_aligned(void)
            {
                char *buf = (char *)malloc(17);
                if (!buf)
                    return;
                buf[24] = 1;
                buf[31] = 2;
                free(buf);
            }

            int main(void)
            {
                safe_aligned();
                return 0;
            }
        '''),
    },
]
