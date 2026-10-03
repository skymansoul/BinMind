"""格式化字符串样本定义 (漏洞 9-16) — 生成样本集的源数据。"""

import textwrap

SAMPLE_DEFS_B = [

    # 9. vsnprintf 污点格式
    {
        'name': 'FMT-009_vsnprintf_taint',
        'cve': '',
        'category': 'fmt',
        'func': 'vlog_trigger',
        'truth': {'is_vuln': True, 'pattern': 'tainted_format_sink',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': 'vsnprintf 的格式参数为外部可控串 — 写越界风险。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdarg.h>

            static void vlog_trigger(const char *fmt, va_list ap)
            {
                char buf[128];
                vsnprintf(buf, sizeof(buf), fmt, ap);
            }

            static void log_wrap(const char *fmt, ...)
            {
                va_list ap;
                va_start(ap, fmt);
                vlog_trigger(fmt, ap);
                va_end(ap);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                log_wrap(argv[1]);
                return 0;
            }
        '''),
    },

    # 10. snprintf 污点格式
    {
        'name': 'FMT-010_snprintf_taint',
        'cve': '',
        'category': 'fmt',
        'func': 'snp_trigger',
        'truth': {'is_vuln': True, 'pattern': 'tainted_format_sink',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': 'snprintf 的格式参数为外部可控串 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void snp_trigger(const char *fmt, int n)
            {
                char buf[128];
                snprintf(buf, sizeof(buf), fmt, n);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                snp_trigger(argv[1], atoi(argv[2]));
                return 0;
            }
        '''),
    },

    # 11. sprintf 污点格式
    {
        'name': 'FMT-011_sprintf_taint',
        'cve': '',
        'category': 'fmt',
        'func': 'sp_trigger',
        'truth': {'is_vuln': True, 'pattern': 'tainted_format_sink',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': 'sprintf 的格式参数为外部可控串 — 越界写。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void sp_trigger(const char *fmt, int n)
            {
                char buf[128];
                sprintf(buf, fmt, n);
            }

            int main(int argc, char **argv)
            {
                if (argc < 3)
                    return 1;
                sp_trigger(argv[1], atoi(argv[2]));
                return 0;
            }
        '''),
    },

    # 12. 数组元素格式串
    {
        'name': 'FMT-012_array_element',
        'cve': '',
        'category': 'fmt',
        'func': 'arr_trigger',
        'truth': {'is_vuln': True, 'pattern': 'tainted_array_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': '从污点数组取元素作为格式串 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <string.h>

            static void arr_trigger(const char *input)
            {
                char *slots[4];
                slots[0] = (char *)input;
                printf(slots[0]);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                arr_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 13. 偏移指针格式串
    {
        'name': 'FMT-013_offset_format',
        'cve': '',
        'category': 'fmt',
        'func': 'off_trigger',
        'truth': {'is_vuln': True, 'pattern': 'tainted_pointer_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': '指向用户数据的偏移指针作为格式串 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <string.h>

            static void off_trigger(const char *input)
            {
                char buf[128];
                strncpy(buf, input, sizeof(buf) - 1);
                buf[sizeof(buf) - 1] = '\\0';
                printf(buf + 0);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                off_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 14. 全局缓冲格式串
    {
        'name': 'FMT-014_global_buffer',
        'cve': '',
        'category': 'fmt',
        'func': 'global_trigger',
        'truth': {'is_vuln': True, 'pattern': 'global_taint_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': '全局缓冲被用户数据填充后作为格式串 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <string.h>

            static char g_buf[128];

            static void global_trigger(const char *input)
            {
                strcpy(g_buf, input);
                printf(g_buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                global_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 15. 拼接格式串
    {
        'name': 'FMT-015_concat_format',
        'cve': '',
        'category': 'fmt',
        'func': 'concat_trigger',
        'truth': {'is_vuln': True, 'pattern': 'concat_taint_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': '把用户数据拼接进格式串后输出 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <string.h>

            static void concat_trigger(const char *input)
            {
                char buf[128];
                strcpy(buf, "log: ");
                strcat(buf, input);
                printf(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                concat_trigger(argv[1]);
                return 0;
            }
        '''),
    },

    # 16. 循环逐字填充格式串
    {
        'name': 'FMT-016_loop_format',
        'cve': '',
        'category': 'fmt',
        'func': 'loop_trigger',
        'truth': {'is_vuln': True, 'pattern': 'loop_taint_format',
                  'overflow_kind': 'fmt', 'cwe': 'CWE-134'},
        'readme': '循环把用户字节填入缓冲后作为格式串 — 格式串攻击。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <string.h>

            static void loop_trigger(const char *input)
            {
                char buf[64];
                size_t i, n = strlen(input);
                for (i = 0; i < n && i < sizeof(buf) - 1; i++)
                    buf[i] = input[i];
                buf[i] = '\\0';
                printf(buf);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                loop_trigger(argv[1]);
                return 0;
            }
        '''),
    },
]
